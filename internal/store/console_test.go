package store

import (
	"testing"

	"github.com/avaadrian/sbs/internal/api"
)

func TestDesiredModeAndStatus(t *testing.T) {
	st := open(t)

	// Setting a mode on an unknown host fails.
	if err := st.SetDesiredMode("nope", "auto"); err != ErrNotFound {
		t.Fatalf("set mode on unknown host: want ErrNotFound, got %v", err)
	}
	// GetDesiredMode on an unknown host is "" with no error.
	if m, err := st.GetDesiredMode("nope"); err != nil || m != "" {
		t.Fatalf("get mode unknown host: %q, %v", m, err)
	}

	if err := st.UpsertHost(api.Host{ID: "h1", Hostname: "web01"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetDesiredMode("h1", "ask"); err != nil {
		t.Fatal(err)
	}
	if m, _ := st.GetDesiredMode("h1"); m != "ask" {
		t.Fatalf("desired mode: %q, want ask", m)
	}

	// Heartbeat status round-trips via ListHosts.
	if err := st.SetHostStatus("h1", "abc123", "parse error", true); err != nil {
		t.Fatal(err)
	}
	// Upsert must preserve the operator override and heartbeat status.
	if err := st.UpsertHost(api.Host{ID: "h1", Hostname: "web01-renamed"}); err != nil {
		t.Fatal(err)
	}
	hosts, _ := st.ListHosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts: %d", len(hosts))
	}
	h := hosts[0]
	if h.DesiredMode != "ask" || h.RulesVersion != "abc123" || h.RulesError != "parse error" || !h.AutoResponseTripped {
		t.Fatalf("host status not preserved: %+v", h)
	}

	// Clearing the override.
	if err := st.SetDesiredMode("h1", ""); err != nil {
		t.Fatal(err)
	}
	if m, _ := st.GetDesiredMode("h1"); m != "" {
		t.Fatalf("mode after clear: %q", m)
	}
}

func TestCustomRuleStore(t *testing.T) {
	st := open(t)

	const y1 = "- id: CR-1\n  title: one\n  event: process"
	const y2 = "- id: CR-2\n  title: two\n  event: file"

	if err := st.AddCustomRule(CustomRule{ID: "a", RuleID: "CR-1", Title: "one", Event: "process", YAML: y1, Enabled: true, Source: "manual"}); err != nil {
		t.Fatal(err)
	}
	// Duplicate rule_id is rejected.
	if err := st.AddCustomRule(CustomRule{ID: "b", RuleID: "CR-1", YAML: y1, Enabled: true}); err != ErrDuplicate {
		t.Fatalf("duplicate rule_id: want ErrDuplicate, got %v", err)
	}
	if err := st.AddCustomRule(CustomRule{ID: "c", RuleID: "CR-2", Title: "two", Event: "file", YAML: y2, Enabled: true, Source: "ai"}); err != nil {
		t.Fatal(err)
	}

	list, err := st.ListCustomRules()
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %d (%v)", len(list), err)
	}

	// Both enabled -> concatenated YAML, stable ordering by rule_id.
	y, err := st.EnabledRuleYAML()
	if err != nil {
		t.Fatal(err)
	}
	if y != y1+"\n"+y2 {
		t.Fatalf("enabled YAML:\n%q", y)
	}

	// Disable one -> only the other is served.
	if _, err := st.SetCustomRuleEnabled("a", false); err != nil {
		t.Fatal(err)
	}
	y, _ = st.EnabledRuleYAML()
	if y != y2 {
		t.Fatalf("enabled YAML after disable:\n%q", y)
	}

	// Enabled flag persists on read-back.
	got, err := st.GetCustomRule("a")
	if err != nil || got.Enabled {
		t.Fatalf("get rule a: %+v (%v)", got, err)
	}

	// Delete.
	if err := st.DeleteCustomRule("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetCustomRule("a"); err != ErrNotFound {
		t.Fatalf("get deleted rule: want ErrNotFound, got %v", err)
	}
	if err := st.DeleteCustomRule("a"); err != ErrNotFound {
		t.Fatalf("delete missing rule: want ErrNotFound, got %v", err)
	}
}
