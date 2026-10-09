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
	mu         sync.Mutex
	configured string      // mode from config; a cleared ("") server override reverts here
	override   string      // last non-empty server override, "" when none
	tripped    bool        // breaker has downgraded auto -> ask
	effective  string      // cached result of recompute, read by mode()
	maxPerMin  int         // auto-action cap per 60s; <= 0 disables the breaker
	window     []time.Time // timestamps of recent executed auto actions
}

// newRespState builds the state from the configured mode and the per-minute
// auto-action cap.
func newRespState(configured string, maxPerMin int) *respState {
	s := &respState{configured: configured, maxPerMin: maxPerMin}
	s.recompute()
	return s
}

// recompute derives the effective mode from the configured mode, any server
// override, and the breaker. Call with s.mu held.
func (s *respState) recompute() {
	base := s.configured
	if s.override != "" {
		base = s.override
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
// the configured mode and clears the breaker (operator-driven reset); an empty
// mode drops the override and reverts to the configured mode. It returns the
// mode before and after and whether it changed, for the caller to log.
func (s *respState) applyOverride(mode string) (from, to string, changed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	from = s.effective
	if mode != "" {
		s.override = mode
		s.tripped = false
	} else {
		s.override = ""
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
