package store

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/avaadrian/sbs/internal/api"
	"github.com/avaadrian/sbs/internal/event"
)

func open(t *testing.T) *Store {
	t.Helper()
	st, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func mkAlert(id, sev string, at time.Time) *event.Alert {
	return &event.Alert{
		ID:       id,
		Time:     at,
		RuleID:   "SBS-PROC-003",
		Title:    "reverse shell",
		Severity: sev,
		MITRE:    []string{"T1059.004"},
		Event: &event.Event{
			Type:    event.TypeProcess,
			Source:  "netlink",
			Process: &event.Process{PID: 42, Exe: "/bin/sh", Comm: "sh"},
		},
	}
}

func TestHostUpsert(t *testing.T) {
	st := open(t)
	h := api.Host{ID: "h1", Hostname: "web01", OS: "Debian", Arch: "amd64", IPs: []string{"10.0.0.1"}}
	if err := st.UpsertHost(h); err != nil {
		t.Fatal(err)
	}
	hosts, err := st.ListHosts()
	if err != nil || len(hosts) != 1 {
		t.Fatalf("ListHosts: %v, %d hosts", err, len(hosts))
	}
	first := hosts[0].FirstSeen
	if hosts[0].Hostname != "web01" || len(hosts[0].IPs) != 1 {
		t.Fatalf("bad host readback: %+v", hosts[0])
	}
	time.Sleep(2 * time.Millisecond)
	h.Hostname = "web01-renamed"
	if err := st.UpsertHost(h); err != nil {
		t.Fatal(err)
	}
	hosts, _ = st.ListHosts()
	if len(hosts) != 1 {
		t.Fatalf("upsert created a duplicate: %d", len(hosts))
	}
	if hosts[0].Hostname != "web01-renamed" {
		t.Fatalf("hostname not updated: %q", hosts[0].Hostname)
	}
	if !hosts[0].FirstSeen.Equal(first) {
		t.Fatalf("first_seen changed: %v -> %v", first, hosts[0].FirstSeen)
	}
	if !hosts[0].LastSeen.After(first) {
		t.Fatalf("last_seen not advanced: first=%v last=%v", first, hosts[0].LastSeen)
	}
}

func TestInsertAlertsDedupe(t *testing.T) {
	st := open(t)
	now := time.Now().UTC()
	a := mkAlert("a1", "high", now)
	acc, dup, err := st.InsertAlerts("h1", []*event.Alert{a})
	if err != nil || acc != 1 || dup != 0 {
		t.Fatalf("first insert: acc=%d dup=%d err=%v", acc, dup, err)
	}
	// Same ID again -> one duplicate, nothing accepted.
	acc, dup, err = st.InsertAlerts("h1", []*event.Alert{mkAlert("a1", "high", now)})
	if err != nil || acc != 0 || dup != 1 {
		t.Fatalf("dup insert: acc=%d dup=%d err=%v", acc, dup, err)
	}
	// Mixed batch: one new, one repeat.
	acc, dup, err = st.InsertAlerts("h1", []*event.Alert{mkAlert("a1", "high", now), mkAlert("a2", "low", now)})
	if err != nil || acc != 1 || dup != 1 {
		t.Fatalf("mixed insert: acc=%d dup=%d err=%v", acc, dup, err)
	}
	got, err := st.GetAlert("a1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "h1" || got.RuleID != "SBS-PROC-003" || got.Event == nil || got.Event.Process.PID != 42 {
		t.Fatalf("alert readback wrong: %+v", got)
	}
	if _, err := st.GetAlert("nope"); err != ErrNotFound {
		t.Fatalf("missing alert: want ErrNotFound, got %v", err)
	}
}

func TestListAlertsFilterAndOrder(t *testing.T) {
	st := open(t)
	base := time.Now().UTC()
	// a_old (low), a_mid (high), a_new (critical) on h1; a_other (high) on h2.
	st.InsertAlerts("h1", []*event.Alert{mkAlert("a_old", "low", base.Add(-2*time.Hour))})
	st.InsertAlerts("h1", []*event.Alert{mkAlert("a_mid", "high", base.Add(-1*time.Hour))})
	st.InsertAlerts("h1", []*event.Alert{mkAlert("a_new", "critical", base)})
	st.InsertAlerts("h2", []*event.Alert{mkAlert("a_other", "high", base)})

	all, err := st.ListAlerts(AlertFilter{})
	if err != nil || len(all) != 4 {
		t.Fatalf("list all: %v, %d", err, len(all))
	}
	if all[0].ID != "a_new" && all[0].ID != "a_other" {
		t.Fatalf("not newest-first: %s", all[0].ID)
	}
	// Oldest must be last.
	if all[len(all)-1].ID != "a_old" {
		t.Fatalf("oldest not last: %s", all[len(all)-1].ID)
	}

	byHost, _ := st.ListAlerts(AlertFilter{HostID: "h1"})
	if len(byHost) != 3 {
		t.Fatalf("host filter: %d", len(byHost))
	}
	bySev, _ := st.ListAlerts(AlertFilter{Severity: "high"})
	if len(bySev) != 2 {
		t.Fatalf("severity filter: %d", len(bySev))
	}
	since, _ := st.ListAlerts(AlertFilter{Since: base.Add(-30 * time.Minute)})
	if len(since) != 2 {
		t.Fatalf("since filter: %d", len(since))
	}
	lim, _ := st.ListAlerts(AlertFilter{Limit: 1})
	if len(lim) != 1 {
		t.Fatalf("limit: %d", len(lim))
	}

	counts, err := st.CountsBySeverity(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if counts["high"] != 2 || counts["low"] != 1 || counts["critical"] != 1 {
		t.Fatalf("counts: %+v", counts)
	}
	recent, _ := st.CountsBySeverity(base.Add(-30 * time.Minute))
	if recent["low"] != 0 || recent["critical"] != 1 || recent["high"] != 1 {
		t.Fatalf("recent counts: %+v", recent)
	}
}

func TestTriageSetGet(t *testing.T) {
	st := open(t)
	st.InsertAlerts("h1", []*event.Alert{mkAlert("a1", "high", time.Now().UTC())})
	payload := map[string]any{"verdict": "malicious", "confidence": 0.9}
	raw, _ := json.Marshal(payload)
	if err := st.SetTriage("a1", raw); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetAlert("a1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Triage) == 0 {
		t.Fatal("triage not stored")
	}
	var back map[string]any
	if err := json.Unmarshal(got.Triage, &back); err != nil {
		t.Fatalf("triage not valid json: %v", err)
	}
	if back["verdict"] != "malicious" {
		t.Fatalf("triage verdict: %v", back["verdict"])
	}
	if err := st.SetTriage("missing", raw); err != ErrNotFound {
		t.Fatalf("triage on missing alert: want ErrNotFound, got %v", err)
	}
}

func TestCommandQueueLifecycle(t *testing.T) {
	st := open(t)
	c1 := api.Command{ID: "c1", Type: api.CmdKill, PID: 1234, Reason: "malware", Created: time.Now().UTC()}
	c2 := api.Command{ID: "c2", Type: api.CmdQuarantine, Path: "/tmp/x", Created: time.Now().UTC().Add(time.Millisecond)}
	if err := st.EnqueueCommand("h1", c1); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueCommand("h1", c2); err != nil {
		t.Fatal(err)
	}
	// A command for a different host must not leak into h1's queue.
	if err := st.EnqueueCommand("h2", api.Command{ID: "c3", Type: api.CmdScan, Path: "/home"}); err != nil {
		t.Fatal(err)
	}

	pending, err := st.PendingCommands("h1")
	if err != nil || len(pending) != 2 {
		t.Fatalf("pending: %v, %d", err, len(pending))
	}
	if pending[0].ID != "c1" || pending[1].ID != "c2" {
		t.Fatalf("pending order: %s, %s", pending[0].ID, pending[1].ID)
	}
	if pending[0].Type != api.CmdKill || pending[0].PID != 1234 {
		t.Fatalf("command fields lost: %+v", pending[0])
	}
	// They were marked sent, so a second poll returns nothing.
	again, err := st.PendingCommands("h1")
	if err != nil || len(again) != 0 {
		t.Fatalf("second poll: %v, %d", err, len(again))
	}

	// Complete one ok, one failed.
	if err := st.CompleteCommand(api.CommandResult{HostID: "h1", CommandID: "c1", OK: true, Output: "killed"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteCommand(api.CommandResult{HostID: "h1", CommandID: "c2", OK: false, Error: "not found"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteCommand(api.CommandResult{CommandID: "ghost"}); err != ErrNotFound {
		t.Fatalf("complete missing: want ErrNotFound, got %v", err)
	}

	// Verify stored status/output directly.
	var status, output string
	if err := st.db.QueryRow("SELECT status, output FROM commands WHERE id='c1'").Scan(&status, &output); err != nil {
		t.Fatal(err)
	}
	if status != StatusDone || output != "killed" {
		t.Fatalf("c1 completion: status=%q output=%q", status, output)
	}
	if err := st.db.QueryRow("SELECT status, output FROM commands WHERE id='c2'").Scan(&status, &output); err != nil {
		t.Fatal(err)
	}
	if status != StatusFailed || output == "" {
		t.Fatalf("c2 completion: status=%q output=%q", status, output)
	}
}
