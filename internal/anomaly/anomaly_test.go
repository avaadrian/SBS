package anomaly

import (
	"testing"
	"time"

	"github.com/avaadrian/sbs/internal/event"
)

func procEvent(exe, parent string, ts time.Time) *event.Event {
	return &event.Event{
		Time:    ts,
		Type:    event.TypeProcess,
		Source:  "test",
		Process: &event.Process{Exe: exe, ParentExe: parent},
	}
}

func TestNewbinWarmupAndSuspicious(t *testing.T) {
	d := New(t.TempDir())
	d.Warmup = 3
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// During warmup (total <= Warmup) even a suspicious new binary is silent.
	for _, exe := range []string{"/tmp/w1", "/tmp/w2", "/usr/bin/ls"} {
		if a := d.Observe(procEvent(exe, "/usr/bin/bash", ts)); a != nil {
			t.Fatalf("alert during warmup for %s: %+v", exe, a)
		}
	}

	// Post-warmup: a new binary from a suspicious root fires NEWBIN (low).
	a := d.Observe(procEvent("/tmp/evil", "/usr/bin/bash", ts))
	if a == nil || a.RuleID != "SBS-ANOM-NEWBIN" {
		t.Fatalf("expected NEWBIN, got %+v", a)
	}
	if a.Severity != "low" {
		t.Fatalf("severity = %q, want low", a.Severity)
	}
	if a.Event == nil || a.Event.Process.Exe != "/tmp/evil" {
		t.Fatalf("alert should carry the triggering event")
	}

	// A new binary from a normal location does not fire.
	if a := d.Observe(procEvent("/usr/bin/curl", "/usr/bin/bash", ts)); a != nil {
		t.Fatalf("non-suspicious new binary fired: %+v", a)
	}

	// Re-running the same suspicious binary does not fire again.
	if a := d.Observe(procEvent("/tmp/evil", "/usr/bin/bash", ts)); a != nil {
		t.Fatalf("already-seen binary fired: %+v", a)
	}

	// A deleted/memfd binary fires NEWBIN at medium severity even though it is
	// not under a suspicious root.
	a = d.Observe(procEvent("/memfd:payload (deleted)", "/usr/bin/bash", ts))
	if a == nil || a.RuleID != "SBS-ANOM-NEWBIN" || a.Severity != "medium" {
		t.Fatalf("expected memfd NEWBIN medium, got %+v", a)
	}
}

func TestFanoutThresholdAndRearm(t *testing.T) {
	d := New(t.TempDir())
	d.Warmup = 0 // post-warmup immediately
	d.Fanout = 5
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// A non-suspicious exe so NEWBIN never interferes. Ten children of one
	// parent inside the window should fire FANOUT exactly once.
	burst := func(start time.Time) int {
		fired := 0
		for i := 0; i < 10; i++ {
			ev := procEvent("/usr/bin/worker", "/usr/bin/spawner", start.Add(time.Duration(i)*time.Millisecond))
			if a := d.Observe(ev); a != nil {
				if a.RuleID != "SBS-ANOM-FANOUT" {
					t.Fatalf("unexpected alert: %+v", a)
				}
				fired++
			}
		}
		return fired
	}

	if n := burst(base); n != 1 {
		t.Fatalf("first burst fired %d times, want 1", n)
	}
	// After a gap longer than the window the bucket clears and re-arms.
	if n := burst(base.Add(time.Hour)); n != 1 {
		t.Fatalf("re-armed burst fired %d times, want 1", n)
	}
}

func TestFanoutBelowThresholdSilent(t *testing.T) {
	d := New(t.TempDir())
	d.Warmup = 0
	d.Fanout = 50
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 40; i++ {
		ev := procEvent("/usr/bin/worker", "/usr/bin/spawner", base.Add(time.Duration(i)*time.Millisecond))
		if a := d.Observe(ev); a != nil {
			t.Fatalf("fired below threshold at i=%d: %+v", i, a)
		}
	}
}

func TestPersistSeenAcrossReload(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	d := New(dir)
	d.Warmup = 0
	if a := d.Observe(procEvent("/tmp/remembered", "/usr/bin/bash", ts)); a == nil {
		t.Fatal("expected NEWBIN on first sight")
	}
	d.Save()

	// A fresh detector loads the baseline, so the binary is no longer new.
	d2 := New(dir)
	d2.Warmup = 0
	if a := d2.Observe(procEvent("/tmp/remembered", "/usr/bin/bash", ts)); a != nil {
		t.Fatalf("binary should be remembered across reload: %+v", a)
	}
}
