package llm

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/avaadrian/sbs/internal/event"
	"github.com/avaadrian/sbs/internal/rules"
)

func TestMockImplementsAnalyst(t *testing.T) {
	var a Analyst = Mock{}
	if a.Name() != "mock" {
		t.Fatalf("Name() = %q, want mock", a.Name())
	}
}

func TestMockTriageVerdicts(t *testing.T) {
	cases := []struct {
		severity string
		want     string
	}{
		{"critical", VerdictMalicious},
		{"high", VerdictMalicious},
		{"medium", VerdictSuspicious},
		{"low", VerdictBenign},
		{"info", VerdictBenign},
	}
	for _, c := range cases {
		in := TriageInput{Alert: &event.Alert{RuleID: "SBS-X-1", Title: "t", Severity: c.severity}}
		tr, err := Mock{}.Triage(context.Background(), in)
		if err != nil {
			t.Fatalf("Triage(%s): %v", c.severity, err)
		}
		if tr.Verdict != c.want {
			t.Errorf("severity %s: verdict = %q, want %q", c.severity, tr.Verdict, c.want)
		}
		if tr.Confidence < 0 || tr.Confidence > 1 {
			t.Errorf("severity %s: confidence %v out of range", c.severity, tr.Confidence)
		}
		if !strings.Contains(tr.Summary, "SBS-X-1") {
			t.Errorf("severity %s: summary %q should echo rule id", c.severity, tr.Summary)
		}
		if tr.Model != "mock" {
			t.Errorf("model = %q, want mock", tr.Model)
		}
	}
}

func TestMockTriageNilAlert(t *testing.T) {
	if _, err := (Mock{}).Triage(context.Background(), TriageInput{}); err == nil {
		t.Fatalf("expected error for nil alert")
	}
}

func TestMockGenerateRuleParses(t *testing.T) {
	gr, err := Mock{}.GenerateRule(context.Background(), "detect curl piped to bash from a webserver")
	if err != nil {
		t.Fatalf("GenerateRule: %v", err)
	}
	if !gr.Valid {
		t.Fatalf("expected valid rule, got validation error %q", gr.ValidationError)
	}
	if _, perr := rules.Parse([]byte(gr.YAML), "generated"); perr != nil {
		t.Fatalf("generated rule does not parse: %v\n%s", perr, gr.YAML)
	}
	if gr.Model != "mock" {
		t.Fatalf("model = %q, want mock", gr.Model)
	}
}

func TestMockSummarizeIncident(t *testing.T) {
	alerts := []*event.Alert{
		{RuleID: "SBS-A", Title: "exec", Severity: "medium", Time: time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC), MITRE: []string{"T1059"}},
		{RuleID: "SBS-B", Title: "persist", Severity: "critical", Time: time.Date(2026, 10, 9, 9, 5, 0, 0, time.UTC), MITRE: []string{"T1053"}},
	}
	is, err := Mock{}.SummarizeIncident(context.Background(), "web-01", alerts)
	if err != nil {
		t.Fatalf("SummarizeIncident: %v", err)
	}
	if len(is.Timeline) != 2 {
		t.Fatalf("timeline length = %d, want 2", len(is.Timeline))
	}
	if is.Severity != "critical" {
		t.Fatalf("severity = %q, want critical", is.Severity)
	}
	if !strings.Contains(is.Timeline[0], "SBS-A") {
		t.Fatalf("timeline[0] = %q should reference first alert", is.Timeline[0])
	}
	if len(is.MITRE) != 2 {
		t.Fatalf("mitre = %v, want 2 entries", is.MITRE)
	}
}

func TestMockSummarizeIncidentEmpty(t *testing.T) {
	if _, err := (Mock{}).SummarizeIncident(context.Background(), "h", nil); err == nil {
		t.Fatalf("expected error for empty alert slice")
	}
}
