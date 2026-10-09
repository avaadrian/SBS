// Package anomaly is a lightweight behavioral layer that complements the
// signature and rule engines. It learns which executables a host normally runs
// and flags two statistical oddities: the first execution of an unknown binary
// from a suspicious location, and a sudden burst of children from one parent.
//
// It is deterministic: given the same event stream it emits the same alerts.
// Its only side effect is a JSON state file under stateDir.
package anomaly

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/avaadrian/sbs/internal/event"
)

// Defaults for the detector's thresholds.
const (
	DefaultWarmup = 200 // processes observed before NEWBIN can fire
	DefaultFanout = 50  // children per parent within the window before FANOUT
)

const (
	fanoutWindow = 5 * time.Second
	maxBuckets   = 8192 // cap on tracked parents; idle ones are swept
	saveEvery    = 64   // persist after this many newly-seen binaries
	stateFile    = "anomaly-seen.json"
)

// suspiciousRoots are directories a legitimate binary rarely runs from.
var suspiciousRoots = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/home/"}

// Detector tracks per-executable rarity and per-parent fan-out. It is safe for
// concurrent use. Warmup and Fanout may be set after New and before use.
type Detector struct {
	stateDir string

	Warmup int // processes to observe before NEWBIN fires
	Fanout int // fan-out threshold per parent

	mu      sync.Mutex
	seen    map[string]bool
	total   int
	dirty   int
	buckets map[string]*bucket
}

// bucket holds the recent start times of one parent's children.
type bucket struct {
	times []time.Time
	fired bool // true once FANOUT fired, until the window clears
}

type persisted struct {
	Seen  []string `json:"seen"`
	Total int      `json:"total"`
}

// New creates a Detector, loading any persisted state from stateDir.
func New(stateDir string) *Detector {
	d := &Detector{
		stateDir: stateDir,
		Warmup:   DefaultWarmup,
		Fanout:   DefaultFanout,
		seen:     map[string]bool{},
		buckets:  map[string]*bucket{},
	}
	d.load()
	return d
}

// Observe records one event and returns an Alert if it is anomalous, else nil.
// Only process events are considered. The returned Alert has no ID; the agent
// pipeline assigns one, as it does for rule and signature alerts.
func (d *Detector) Observe(ev *event.Event) *event.Alert {
	if ev == nil || ev.Process == nil {
		return nil
	}
	p := ev.Process
	d.mu.Lock()
	defer d.mu.Unlock()
	d.total++
	// Update both detectors' state, then prefer the fan-out alert.
	fo := d.fanout(ev, p)
	nb := d.newbin(ev, p)
	if fo != nil {
		return fo
	}
	return nb
}

// newbin flags the first execution of a previously-unseen binary, but only once
// warmup is over and only when the binary runs from a suspicious location or is
// deleted/memfd-backed. It always records the path so the baseline keeps growing.
func (d *Detector) newbin(ev *event.Event, p *event.Process) *event.Alert {
	raw := p.Exe
	if raw == "" {
		return nil
	}
	path := strings.TrimSuffix(raw, " (deleted)")
	first := !d.seen[path]
	if first {
		d.seen[path] = true
		d.dirty++
		if d.dirty >= saveEvery {
			d.saveLocked()
			d.dirty = 0
		}
	}
	if !first || d.total <= d.Warmup {
		return nil
	}
	deletedOrMemfd := strings.Contains(raw, "(deleted)") || strings.Contains(raw, "memfd:")
	if !deletedOrMemfd && !underSuspiciousRoot(path) {
		return nil
	}
	sev := "low"
	if deletedOrMemfd {
		sev = "medium"
	}
	return &event.Alert{
		Time:     eventTime(ev),
		RuleID:   "SBS-ANOM-NEWBIN",
		Title:    "First execution of a binary not seen before",
		Severity: sev,
		MITRE:    []string{"T1204"},
		Event:    ev,
	}
}

// fanout flags an unusual burst of children from one parent executable within
// the window. It fires once per burst, re-arming after the window clears.
func (d *Detector) fanout(ev *event.Event, p *event.Process) *event.Alert {
	parent := p.ParentExe
	if parent == "" {
		return nil
	}
	now := eventTime(ev)
	cutoff := now.Add(-fanoutWindow)
	if len(d.buckets) > maxBuckets {
		d.sweepLocked(cutoff)
	}
	b := d.buckets[parent]
	if b == nil {
		b = &bucket{}
		d.buckets[parent] = b
	}
	// Drop start times that fell out of the window, then record this one.
	kept := b.times[:0]
	for _, t := range b.times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	b.times = append(kept, now)
	if len(b.times) > d.Fanout {
		if b.fired {
			return nil
		}
		b.fired = true
		return &event.Alert{
			Time:     now,
			RuleID:   "SBS-ANOM-FANOUT",
			Title:    "Unusual process fan-out",
			Severity: "medium",
			MITRE:    []string{"T1059"},
			Event:    ev,
		}
	}
	b.fired = false
	return nil
}

// sweepLocked drops parents whose most recent child fell out of the window.
func (d *Detector) sweepLocked(cutoff time.Time) {
	for k, b := range d.buckets {
		if len(b.times) == 0 || !b.times[len(b.times)-1].After(cutoff) {
			delete(d.buckets, k)
		}
	}
}

// Save persists the seen-binary baseline.
func (d *Detector) Save() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.saveLocked()
}

func (d *Detector) load() {
	if d.stateDir == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(d.stateDir, stateFile))
	if err != nil {
		return
	}
	var st persisted
	if json.Unmarshal(data, &st) != nil {
		return
	}
	for _, p := range st.Seen {
		d.seen[p] = true
	}
	d.total = st.Total
}

// saveLocked writes the baseline atomically. Call with d.mu held.
func (d *Detector) saveLocked() {
	if d.stateDir == "" {
		return
	}
	seen := make([]string, 0, len(d.seen))
	for p := range d.seen {
		seen = append(seen, p)
	}
	sort.Strings(seen) // stable file contents
	data, err := json.Marshal(persisted{Seen: seen, Total: d.total})
	if err != nil {
		return
	}
	if err := os.MkdirAll(d.stateDir, 0o700); err != nil {
		return
	}
	tmp := filepath.Join(d.stateDir, "."+stateFile+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	os.Rename(tmp, filepath.Join(d.stateDir, stateFile))
}

func underSuspiciousRoot(path string) bool {
	for _, r := range suspiciousRoots {
		if strings.HasPrefix(path, r) {
			return true
		}
	}
	return false
}

// eventTime uses the event's own timestamp when set, keeping Observe deterministic.
func eventTime(ev *event.Event) time.Time {
	if !ev.Time.IsZero() {
		return ev.Time
	}
	return time.Now().UTC()
}
