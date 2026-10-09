package llm

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/avaadrian/sbs/internal/event"
	"github.com/avaadrian/sbs/internal/rules"
	"gopkg.in/yaml.v3"
)

// Mock is a deterministic, network-free Analyst used by the server and the
// benchmark. Its verdicts follow a fixed rule so tests can assert on them.
type Mock struct{}

// compile-time check that Mock implements Analyst.
var _ Analyst = Mock{}

// Name identifies the mock provider.
func (Mock) Name() string { return "mock" }

// Triage classifies an alert by its severity: critical/high are malicious,
// medium is suspicious, and everything else is benign. The rule ID is echoed
// into the summary.
func (Mock) Triage(ctx context.Context, in TriageInput) (*Triage, error) {
	if in.Alert == nil {
		return nil, fmt.Errorf("llm: mock triage: nil alert")
	}
	a := in.Alert

	var verdict string
	var confidence float64
	switch a.Severity {
	case "critical", "high":
		verdict, confidence = VerdictMalicious, 0.9
	case "medium":
		verdict, confidence = VerdictSuspicious, 0.6
	case "low", "info":
		verdict, confidence = VerdictBenign, 0.2
	default:
		verdict, confidence = VerdictSuspicious, 0.5
	}

	severity := a.Severity
	if !allowedSeverities[severity] {
		severity = "medium"
	}

	return &Triage{
		Verdict:            verdict,
		Confidence:         confidence,
		Severity:           severity,
		Summary:            fmt.Sprintf("%s: rule %s (%s)", verdict, a.RuleID, a.Title),
		Analysis:           fmt.Sprintf("Mock triage classified rule %s as %s based on its %s severity.", a.RuleID, verdict, a.Severity),
		MITRE:              a.MITRE,
		RecommendedActions: []string{"Review the alert and its host context."},
		Model:              "mock",
		Redactions:         redactionCount(in),
		CreatedAt:          time.Now().UTC(),
	}, nil
}

// GenerateRule builds a minimal, always-valid detection rule from the
// description. It validates the rule with rules.Parse so the mock cannot drift
// out of sync with the engine.
func (Mock) GenerateRule(ctx context.Context, description string) (*GeneratedRule, error) {
	title := strings.TrimSpace(description)
	if title == "" {
		title = "Generated rule"
	}
	if len(title) > 120 {
		title = title[:120]
	}

	token := "suspicious"
	if fields := strings.Fields(description); len(fields) > 0 {
		token = fields[0]
	}

	// Marshal through yaml so values are escaped correctly.
	type genMatch struct {
		Field string `yaml:"field"`
		Op    string `yaml:"op"`
		Value string `yaml:"value"`
	}
	type genRule struct {
		ID       string   `yaml:"id"`
		Title    string   `yaml:"title"`
		Severity string   `yaml:"severity"`
		MITRE    []string `yaml:"mitre"`
		Event    string   `yaml:"event"`
		Match    genMatch `yaml:"match"`
	}
	doc, err := yaml.Marshal([]genRule{{
		ID:       "SBS-GEN-MOCK",
		Title:    title,
		Severity: "medium",
		MITRE:    []string{},
		Event:    event.TypeProcess,
		Match:    genMatch{Field: "process.cmdline", Op: "contains", Value: token},
	}})
	if err != nil {
		return nil, fmt.Errorf("llm: mock generate rule: %w", err)
	}

	gr := &GeneratedRule{
		YAML:        string(doc),
		Explanation: fmt.Sprintf("Mock rule that flags processes whose command line contains %q.", token),
		Attempts:    1,
		Model:       "mock",
	}
	if _, perr := rules.Parse(doc, "generated"); perr != nil {
		gr.ValidationError = perr.Error()
		return gr, nil
	}
	gr.Valid = true
	return gr, nil
}

// SummarizeIncident builds a timeline from the alert times and a severity from
// the most severe alert.
func (Mock) SummarizeIncident(ctx context.Context, host string, alerts []*event.Alert) (*IncidentSummary, error) {
	if len(alerts) == 0 {
		return nil, fmt.Errorf("llm: mock summarize: no alerts")
	}

	timeline := make([]string, 0, len(alerts))
	for _, a := range alerts {
		if a == nil {
			continue
		}
		ts := "unknown time"
		if !a.Time.IsZero() {
			ts = a.Time.UTC().Format("2006-01-02T15:04:05Z")
		}
		timeline = append(timeline, fmt.Sprintf("%s — %s (%s)", ts, a.Title, a.RuleID))
	}

	hostLabel := host
	if hostLabel == "" {
		hostLabel = "the host"
	}

	return &IncidentSummary{
		Title:              fmt.Sprintf("Incident on %s (%d alerts)", hostLabel, len(timeline)),
		Severity:           highestSeverity(alerts),
		Summary:            fmt.Sprintf("Mock summary of %d related alerts on %s.", len(timeline), hostLabel),
		Timeline:           timeline,
		MITRE:              collectMITRE(alerts),
		RecommendedActions: []string{"Investigate the host and contain if confirmed malicious."},
		Model:              "mock",
		CreatedAt:          time.Now().UTC(),
	}, nil
}

// redactionCount reports how many secrets the triage prompt would mask, so the
// mock's Redactions field is as honest as the real analyst's.
func redactionCount(in TriageInput) int {
	_, n := buildTriageUser(in)
	return n
}
