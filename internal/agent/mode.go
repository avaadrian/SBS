package agent

import (
	"sync"
	"time"
)

// respState tracks the agent's live response mode and the auto-response circuit
// breaker. The effective mode is initialised from config, can be overridden by
// the server at runtime, and is downgraded from auto to ask by the breaker when
// too many automatic actions fire. It is read on the event loop (respond, the
// heartbeat host snapshot) and written by the heartbeat goroutine (server
// overrides) and the event loop (breaker), so every access takes the mutex.
type respState struct {
	mu            sync.Mutex
	configured    string      // mode from config; a cleared ("") server override reverts here
	override      string      // last non-empty server override, "" when none
	allowOverride bool        // may a server override RAISE capability above configured?
	tripped       bool        // breaker has downgraded auto -> ask
	effective     string      // cached result of recompute, read by mode()
	maxPerMin     int         // auto-action cap per 60s; <= 0 disables the breaker
	window        []time.Time // timestamps of recent executed auto actions
}

// modeRank orders the response modes by capability so a server override cannot
// raise an agent above its configured mode unless explicitly allowed.
func modeRank(m string) int {
	switch m {
	case ModeAsk:
		return 1
	case ModeAuto:
		return 2
	default: // off and unknown
		return 0
	}
}

// newRespState builds the state from the configured mode, the per-minute
// auto-action cap, and whether a server override may raise capability.
func newRespState(configured string, maxPerMin int, allowOverride bool) *respState {
	s := &respState{configured: configured, maxPerMin: maxPerMin, allowOverride: allowOverride}
	s.recompute()
	return s
}

// recompute derives the effective mode from the configured mode, any server
// override, and the breaker. A server override may always lower capability
// (toward off, a safe kill switch) but may only raise it above the configured
// mode when allowOverride is set, so a compromised control plane cannot turn a
// deliberately off/ask agent into an auto-killer. Call with s.mu held.
func (s *respState) recompute() {
	base := s.configured
	if s.override != "" {
		base = s.override
		if !s.allowOverride && modeRank(base) > modeRank(s.configured) {
			base = s.configured // clamp to the operator's ceiling
		}
	}
	if s.tripped && base == ModeAuto {
		base = ModeAsk
	}
	s.effective = base
}

// mode returns the current effective response mode.
func (s *respState) mode() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.effective
}

// tripped reports whether the breaker has downgraded the agent.
func (s *respState) breakerTripped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tripped
}

// applyOverride applies a server-sent response mode. A non-empty mode overrides
// the configured mode; an empty mode drops the override and reverts. The breaker
// is cleared only on an actual override transition (a change in the override
// value), not on every heartbeat that repeats the same override — otherwise a
// persisted auto override would re-arm the breaker each heartbeat and defeat it.
// It returns the mode before and after and whether the effective mode changed.
func (s *respState) applyOverride(mode string) (from, to string, changed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	from = s.effective
	prev := s.override
	if mode != "" {
		s.override = mode
	} else {
		s.override = ""
	}
	if s.override != prev {
		s.tripped = false // operator-driven reset on a genuine mode change
	}
	s.recompute()
	to = s.effective
	return from, to, from != to
}

// reserveAuto reserves capacity for n executed auto actions within the sliding
// 60s window. It returns true when they fit under the cap (and records them);
// when they would exceed the cap it trips the breaker, downgrading auto -> ask,
// and returns false. The second result reports whether this call tripped it.
func (s *respState) reserveAuto(n int, now time.Time) (ok, tripped bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxPerMin <= 0 { // breaker disabled
		return true, false
	}
	cutoff := now.Add(-time.Minute)
	kept := s.window[:0]
	for _, t := range s.window {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	s.window = kept
	if len(s.window)+n > s.maxPerMin {
		if !s.tripped {
			s.tripped = true
			s.recompute()
			tripped = true
		}
		return false, tripped
	}
	for i := 0; i < n; i++ {
		s.window = append(s.window, now)
	}
	return true, false
}

// proposals tracks the response actions the agent proposed in ask mode but has
// not executed, so that a server kill/quarantine command is honored only when
// it matches a proposal the agent actually made (the operator approving the
// agent's own proposal). Without this, an attacker who controls the server
// could inject arbitrary kills/quarantines at an ask-mode agent even with
// remote_commands disabled.
type proposals struct {
	mu  sync.Mutex
	m   map[string]proposal // keyed by alert ID
	ttl time.Duration
	max int
}

type proposal struct {
	kind string // api.CmdKill | api.CmdQuarantine
	pid  int
	path string
	at   time.Time
}

func newProposals() *proposals {
	return &proposals{m: map[string]proposal{}, ttl: 10 * time.Minute, max: 4096}
}

// record notes a proposed action for an alert.
func (p *proposals) record(alertID, kind string, pid int, path string) {
	if alertID == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if len(p.m) >= p.max {
		for k, v := range p.m { // drop the oldest / any expired to stay bounded
			if now.Sub(v.at) > p.ttl || len(p.m) >= p.max {
				delete(p.m, k)
			}
		}
	}
	p.m[alertID+"|"+kind] = proposal{kind: kind, pid: pid, path: path, at: now}
}

// consume reports whether the agent proposed exactly this action for this alert
// and, if so, removes it (single-use). A command that does not match a live
// proposal is refused by the caller unless remote commands are enabled.
func (p *proposals) consume(alertID, kind string, pid int, path string) bool {
	if alertID == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key := alertID + "|" + kind
	pr, ok := p.m[key]
	if !ok || time.Since(pr.at) > p.ttl {
		delete(p.m, key)
		return false
	}
	match := (kind == "kill" && pr.pid == pid && pid > 0) ||
		(kind == "quarantine" && pr.path == path && path != "")
	if match {
		delete(p.m, key)
	}
	return match
}
