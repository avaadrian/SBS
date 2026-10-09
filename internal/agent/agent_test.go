package agent

import (
	"context"
	"encoding/json"
	"github.com/avaadrian/sbs/assets"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/avaadrian/sbs/internal/api"
	"github.com/avaadrian/sbs/internal/event"
	"github.com/avaadrian/sbs/internal/rules"
	"github.com/avaadrian/sbs/internal/scanner"
)

func noSigs(*scanner.Scanner) error { return nil }

// testConfig returns a config that writes alerts to a temp file and skips the
// built-in rules/signatures, for a self-contained agent.
func testConfig(t *testing.T, mode string) Config {
	t.Helper()
	cfg := DefaultConfig()
	cfg.NoDefaults = true
	cfg.Watch = nil
	cfg.Anomaly.Enabled = false
	cfg.Response.Mode = mode
	cfg.AlertsPath = filepath.Join(t.TempDir(), "alerts.jsonl")
	return cfg
}

func procAlert(pid int) *event.Alert {
	return &event.Alert{
		RuleID:   "SBS-TEST",
		Severity: "critical",
		Event:    &event.Event{Type: event.TypeProcess, Process: &event.Process{PID: pid}},
	}
}

// --- respState unit tests ------------------------------------------------

func TestRespStateOverrideAndRevert(t *testing.T) {
	s := newRespState(ModeAuto, 10, false)
	if got := s.mode(); got != ModeAuto {
		t.Fatalf("initial mode = %q, want auto", got)
	}
	if from, to, changed := s.applyOverride(ModeOff); !changed || from != ModeAuto || to != ModeOff {
		t.Fatalf("applyOverride(off) = %q,%q,%v", from, to, changed)
	}
	if got := s.mode(); got != ModeOff {
		t.Fatalf("after override mode = %q, want off", got)
	}
	// Empty override reverts to the configured mode.
	if _, to, changed := s.applyOverride(""); !changed || to != ModeAuto {
		t.Fatalf("applyOverride(\"\") to = %q changed=%v, want auto true", to, changed)
	}
	// Re-applying the same effective mode is not a change.
	if _, _, changed := s.applyOverride(ModeAuto); changed {
		t.Fatalf("re-applying auto reported a change")
	}
}

func TestRespStateBreakerTripAndReset(t *testing.T) {
	s := newRespState(ModeAuto, 3, false)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if ok, _ := s.reserveAuto(1, now); !ok {
			t.Fatalf("reserveAuto #%d denied under cap", i)
		}
	}
	// The 4th action exceeds the cap: breaker trips, mode downgrades to ask.
	ok, tripped := s.reserveAuto(1, now)
	if ok || !tripped {
		t.Fatalf("reserveAuto over cap = ok %v tripped %v, want false true", ok, tripped)
	}
	if !s.breakerTripped() {
		t.Fatal("breakerTripped = false after trip")
	}
	if got := s.mode(); got != ModeAsk {
		t.Fatalf("mode after trip = %q, want ask (downgraded)", got)
	}
	// Already tripped: a further reserve stays denied but does not re-report.
	if ok, tripped := s.reserveAuto(1, now); ok || tripped {
		t.Fatalf("reserveAuto while tripped = ok %v tripped %v, want false false", ok, tripped)
	}
	// Operator reset via a server override (even back to auto) clears the breaker.
	s.applyOverride(ModeAuto)
	if s.breakerTripped() {
		t.Fatal("override did not clear breaker")
	}
	if got := s.mode(); got != ModeAuto {
		t.Fatalf("mode after reset = %q, want auto", got)
	}
}

func TestRespStateBreakerSlidingWindow(t *testing.T) {
	s := newRespState(ModeAuto, 3, false)
	t0 := time.Now()
	for i := 0; i < 3; i++ {
		s.reserveAuto(1, t0)
	}
	// 61s later the earlier actions have aged out of the window, so new
	// actions fit again without tripping.
	later := t0.Add(61 * time.Second)
	if ok, tripped := s.reserveAuto(1, later); !ok || tripped {
		t.Fatalf("reserveAuto after window = ok %v tripped %v, want true false", ok, tripped)
	}
}

func TestRespStateBreakerDisabled(t *testing.T) {
	s := newRespState(ModeAuto, -1, false) // negative disables the breaker
	now := time.Now()
	for i := 0; i < 1000; i++ {
		if ok, _ := s.reserveAuto(1, now); !ok {
			t.Fatalf("disabled breaker denied action #%d", i)
		}
	}
	if s.breakerTripped() {
		t.Fatal("disabled breaker reported tripped")
	}
}

// --- Agent-level tests ---------------------------------------------------

func TestMaxAutoDefaultsToTen(t *testing.T) {
	cfg := testConfig(t, ModeAuto)
	cfg.Response.MaxAutoActionsPerMinute = 0 // unset
	a, err := New(cfg, nil, noSigs)
	if err != nil {
		t.Fatal(err)
	}
	if a.resp.maxPerMin != 10 {
		t.Fatalf("maxPerMin = %d, want default 10", a.resp.maxPerMin)
	}
}

func TestApplyResponseMode(t *testing.T) {
	a, err := New(testConfig(t, ModeAuto), nil, noSigs)
	if err != nil {
		t.Fatal(err)
	}
	a.applyResponseMode(ModeAsk)
	if got := a.resp.mode(); got != ModeAsk {
		t.Fatalf("after override mode = %q, want ask", got)
	}
	a.applyResponseMode("bogus") // invalid: ignored
	if got := a.resp.mode(); got != ModeAsk {
		t.Fatalf("invalid override changed mode to %q", got)
	}
	a.applyResponseMode("") // revert to configured (auto)
	if got := a.resp.mode(); got != ModeAuto {
		t.Fatalf("after clear mode = %q, want auto", got)
	}
}

// TestRespondBreakerDowngrade drives respond() in auto mode past the action cap
// and confirms it stops executing and starts proposing. The process PID is the
// test process itself, so Kill refuses it and nothing is actually signalled.
func TestRespondBreakerDowngrade(t *testing.T) {
	cfg := testConfig(t, ModeAuto)
	cfg.Response.MaxAutoActionsPerMinute = 2
	a, err := New(cfg, nil, noSigs)
	if err != nil {
		t.Fatal(err)
	}
	self := os.Getpid()
	// First two alerts are auto-handled (one kill action each).
	for i := 0; i < 2; i++ {
		al := procAlert(self)
		a.respond(al)
		if len(al.Actions) != 1 || len(al.Proposed) != 0 {
			t.Fatalf("alert %d: actions=%d proposed=%d, want 1/0", i, len(al.Actions), len(al.Proposed))
		}
	}
	// Third alert would exceed the cap: breaker trips, alert becomes a proposal.
	al := procAlert(self)
	a.respond(al)
	if len(al.Actions) != 0 || len(al.Proposed) != 1 {
		t.Fatalf("tripping alert: actions=%d proposed=%d, want 0/1", len(al.Actions), len(al.Proposed))
	}
	if !a.resp.breakerTripped() || a.resp.mode() != ModeAsk {
		t.Fatalf("after trip: tripped=%v mode=%q", a.resp.breakerTripped(), a.resp.mode())
	}
	// Subsequent alerts stay proposals until an operator reset.
	al = procAlert(self)
	a.respond(al)
	if len(al.Proposed) != 1 || len(al.Actions) != 0 {
		t.Fatalf("post-trip alert: actions=%d proposed=%d, want 0/1", len(al.Actions), len(al.Proposed))
	}
}

func TestRespondAskProposes(t *testing.T) {
	a, err := New(testConfig(t, ModeAsk), nil, noSigs)
	if err != nil {
		t.Fatal(err)
	}
	al := procAlert(4242)
	a.respond(al)
	if len(al.Proposed) != 1 || al.Proposed[0] != api.CmdKill || len(al.Actions) != 0 {
		t.Fatalf("ask mode: proposed=%v actions=%d", al.Proposed, len(al.Actions))
	}
}

func TestRespondOffViaOverride(t *testing.T) {
	// Configured auto, but a server override to off must stop all response.
	a, err := New(testConfig(t, ModeAuto), nil, noSigs)
	if err != nil {
		t.Fatal(err)
	}
	a.applyResponseMode(ModeOff)
	al := procAlert(os.Getpid())
	a.respond(al)
	if len(al.Actions) != 0 || len(al.Proposed) != 0 {
		t.Fatalf("off override: actions=%d proposed=%d, want 0/0", len(al.Actions), len(al.Proposed))
	}
}

// TestReloadRules exercises the hot-swap path end to end through a real
// transport.Client pointed at a fake server.
func TestReloadRules(t *testing.T) {
	const customYAML = `
- id: SBS-CUSTOM-1
  title: custom download-to-shell
  severity: high
  event: process
  match:
    field: process.cmdline
    op: contains
    value: curl-evil
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != api.PathRules {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(api.RuleSet{Version: "v2", YAML: customYAML})
	}))
	defer srv.Close()

	cfg := testConfig(t, ModeAsk)
	cfg.NoDefaults = false // keep a built-in so we can prove it is retained
	cfg.Server.URL = srv.URL
	cfg.Server.Token = "tok"
	cfg.Server.SpoolDir = t.TempDir()

	builtin, err := rules.Parse([]byte(`
- id: SBS-BUILTIN-1
  title: builtin rule
  severity: medium
  event: file
  match:
    field: file.path
    op: endswith
    value: .suspect
`), "builtin")
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg, builtin, noSigs)
	if err != nil {
		t.Fatal(err)
	}
	if a.Rules() != 1 {
		t.Fatalf("initial rules = %d, want 1 (builtin)", a.Rules())
	}

	a.reloadRules(context.Background(), "v2")
	if a.rulesVersion != "v2" || a.rulesErr != "" {
		t.Fatalf("after reload: version=%q err=%q", a.rulesVersion, a.rulesErr)
	}
	if a.Rules() != 2 {
		t.Fatalf("rules after reload = %d, want 2 (builtin + custom)", a.Rules())
	}
	// The custom rule actually fires.
	hits := a.rules.Load().Evaluate(&event.Event{
		Type:    event.TypeProcess,
		Process: &event.Process{PID: 7, Cmdline: "curl-evil http://x | sh"},
	})
	found := false
	for _, h := range hits {
		if h.RuleID == "SBS-CUSTOM-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("custom rule did not fire; hits=%v", hits)
	}

	// Same version again: no-op (no refetch needed), state unchanged.
	a.reloadRules(context.Background(), "v2")
	if a.Rules() != 2 {
		t.Fatalf("idempotent reload changed rule count to %d", a.Rules())
	}
}

func TestReloadRulesParseErrorKeepsEngine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(api.RuleSet{Version: "bad", YAML: "- id: X\n  title: missing event\n"})
	}))
	defer srv.Close()

	cfg := testConfig(t, ModeAsk)
	cfg.Server.URL = srv.URL
	cfg.Server.Token = "tok"
	cfg.Server.SpoolDir = t.TempDir()
	a, err := New(cfg, nil, noSigs)
	if err != nil {
		t.Fatal(err)
	}
	before := a.rules.Load()
	a.reloadRules(context.Background(), "bad")
	if a.rulesErr == "" {
		t.Fatal("expected rulesErr after a bad rule set")
	}
	// The engine is kept (old rules keep firing), but the version IS adopted so
	// the agent does not refetch and re-fail the same bad set every heartbeat.
	if a.rulesVersion != "bad" {
		t.Fatalf("version = %q, want the adopted bad version to stop refetch loop", a.rulesVersion)
	}
	if a.rules.Load() != before {
		t.Fatal("engine was replaced despite parse error")
	}
}

// TestReloadRulesSkipsCollidingCustomRule verifies a custom rule whose id
// collides with a built-in is skipped (not fatal to the whole set) and the
// version still advances.
func TestReloadRulesSkipsCollidingCustomRule(t *testing.T) {
	// One colliding id (SBS-PROC-001 is a built-in) and one valid custom rule.
	yaml := "- id: SBS-PROC-001\n  title: collide\n  event: process\n  match: {field: process.name, value: x}\n" +
		"- id: CUSTOM-900\n  title: ok\n  event: process\n  match: {field: process.name, value: zzz}\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(api.RuleSet{Version: "v2", YAML: yaml})
	}))
	defer srv.Close()

	builtins, err := assets.Rules()
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t, ModeAsk)
	cfg.NoDefaults = false // load the built-ins so the collision is detected
	cfg.Server.URL = srv.URL
	cfg.Server.Token = "tok"
	cfg.Server.SpoolDir = t.TempDir()
	a, err := New(cfg, builtins, noSigs)
	if err != nil {
		t.Fatal(err)
	}
	a.reloadRules(context.Background(), "v2")
	if a.rulesVersion != "v2" {
		t.Fatalf("version = %q, want v2", a.rulesVersion)
	}
	if a.rulesErr == "" {
		t.Fatal("expected rulesErr noting the skipped colliding rule")
	}
	// The valid custom rule loaded; the built-in SBS-PROC-001 is intact.
	if !a.rules.Load().Has("CUSTOM-900") || !a.rules.Load().Has("SBS-PROC-001") {
		t.Fatal("expected both CUSTOM-900 and the built-in SBS-PROC-001 active")
	}
}

// TestModeAndEngineRaces exercises the guarded state from multiple goroutines so
// `go test -race` can prove respond/heartbeat access is safe.
func TestModeAndEngineRaces(t *testing.T) {
	cfg := testConfig(t, ModeAuto)
	cfg.Response.MaxAutoActionsPerMinute = 5
	a, err := New(cfg, nil, noSigs)
	if err != nil {
		t.Fatal(err)
	}
	eng2, _ := rules.NewEngine(nil)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	// Event-loop side: respond + engine reads.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				a.respond(procAlert(os.Getpid()))
				_ = a.Rules()
			}
		}
	}()
	// Heartbeat side: mode overrides + engine swaps.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			a.applyResponseMode([]string{ModeOff, ModeAsk, ModeAuto, ""}[i%4])
			a.rules.Store(eng2)
			_ = a.resp.breakerTripped()
		}
		close(stop)
	}()
	wg.Wait()
}

// TestRespStateOverrideCeiling verifies a server override may lower capability
// but may only raise it above the configured mode when allowed.
func TestRespStateOverrideCeiling(t *testing.T) {
	// Configured ask, overrides NOT allowed to raise: auto is clamped to ask,
	// off (lowering) is honored.
	s := newRespState(ModeAsk, 10, false)
	if _, to, _ := s.applyOverride(ModeAuto); to != ModeAsk {
		t.Fatalf("auto override on ask ceiling = %q, want ask (clamped)", to)
	}
	if _, to, _ := s.applyOverride(ModeOff); to != ModeOff {
		t.Fatalf("off override = %q, want off (lowering allowed)", to)
	}
	// Configured off is a hard floor without opt-in: nothing raises it.
	s2 := newRespState(ModeOff, 10, false)
	if _, to, _ := s2.applyOverride(ModeAuto); to != ModeOff {
		t.Fatalf("auto override on off floor = %q, want off", to)
	}
	// With opt-in, raising is allowed.
	s3 := newRespState(ModeAsk, 10, true)
	if _, to, _ := s3.applyOverride(ModeAuto); to != ModeAuto {
		t.Fatalf("auto override with allowOverride = %q, want auto", to)
	}
}

// TestProposalsMatch verifies ask-mode commands only match a recorded proposal.
func TestProposalsMatch(t *testing.T) {
	p := newProposals()
	p.record("a1", "kill", 4242, "")
	if p.consume("a1", "kill", 1, "") { // wrong pid
		t.Fatal("consumed with wrong pid")
	}
	if !p.consume("a1", "kill", 4242, "") { // correct
		t.Fatal("did not consume a matching proposal")
	}
	if p.consume("a1", "kill", 4242, "") { // single-use
		t.Fatal("consumed twice")
	}
	if p.consume("nope", "kill", 1, "") {
		t.Fatal("consumed an unrecorded alert")
	}
}
