package anomaly

import (
	"fmt"
	"testing"
	"time"
)

// TestNewBinPreferredOverFanout ensures a first-execution alert is not lost when
// a fan-out burst happens on the same event: NEWBIN can fire only once ever, so
// it must win over the re-armable FANOUT.
func TestNewBinPreferredOverFanout(t *testing.T) {
	d := New(t.TempDir())
	d.Warmup = 0
	d.Fanout = 3
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Drive one parent past the fan-out threshold with an already-seen exe.
	for i := 0; i < 5; i++ {
		d.Observe(procEvent("/bin/seen", "/bin/parent", ts))
	}
	// A brand-new suspicious binary under the same parent, same window: both
	// NEWBIN and FANOUT conditions hold. NEWBIN must win.
	al := d.Observe(procEvent("/tmp/dropper", "/bin/parent", ts))
	if al == nil || al.RuleID != "SBS-ANOM-NEWBIN" {
		t.Fatalf("expected NEWBIN to win, got %+v", al)
	}
}

// TestSeenMapBounded checks the FIFO cap keeps the baseline from growing without
// bound.
func TestSeenMapBounded(t *testing.T) {
	old := maxSeen
	maxSeen = 100
	defer func() { maxSeen = old }()
	d := New(t.TempDir())
	d.stateDir = "" // skip persistence so the test stays fast
	d.Warmup = 0
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < maxSeen+500; i++ {
		d.Observe(procEvent(fmt.Sprintf("/opt/app/bin-%d", i), "/bin/parent", ts))
	}
	if len(d.seen) > maxSeen {
		t.Fatalf("seen map = %d, want <= %d", len(d.seen), maxSeen)
	}
	if len(d.order) > maxSeen {
		t.Fatalf("order = %d, want <= %d", len(d.order), maxSeen)
	}
}
