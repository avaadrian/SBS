// Package llm provides AI-assisted analysis for SBS: alert triage, detection
// rule generation from natural language, and incident summaries.
//
// Everything the model returns is advisory. Event data (command lines, file
// paths) is attacker-controlled and is passed to the model as untrusted data;
// no LLM output may trigger a response action on its own.
package llm

import (
	"context"
	"errors"
	"time"

	"github.com/avaadrian/sbs/internal/event"
)

// ErrDisabled is returned when no provider is configured.
var ErrDisabled = errors.New("llm: analysis disabled (no provider configured)")

// Verdicts.
const (
	VerdictMalicious  = "malicious"
	VerdictSuspicious = "suspicious"
	VerdictBenign     = "benign"
	VerdictUnknown    = "unknown"
)

// TriageInput is one alert plus context from the same host.
type TriageInput struct {
	Alert   *event.Alert   `json:"alert"`
	Host    string         `json:"host,omitempty"`    // hostname / OS description
	Related []*event.Alert `json:"related,omitempty"` // nearby alerts on the same host
}

// Triage is the model's assessment of an alert.
type Triage struct {
	Verdict            string    `json:"verdict"`    // malicious | suspicious | benign | unknown
	Confidence         float64   `json:"confidence"` // 0..1
	Severity           string    `json:"severity"`   // info | low | medium | high | critical
	Summary            string    `json:"summary"`    // one sentence
	Analysis           string    `json:"analysis"`   // why, referencing the evidence
	MITRE              []string  `json:"mitre,omitempty"`
	RecommendedActions []string  `json:"recommended_actions,omitempty"`
	Model              string    `json:"model"`
	InputTokens        int       `json:"input_tokens"`
	OutputTokens       int       `json:"output_tokens"`
	Redactions         int       `json:"redactions"` // secrets masked before sending
	CreatedAt          time.Time `json:"created_at"`
}

// GeneratedRule is a detection rule written from a description and validated
// by the rule engine.
type GeneratedRule struct {
	YAML            string `json:"yaml"`
	Explanation     string `json:"explanation"`
	Valid           bool   `json:"valid"`
	ValidationError string `json:"validation_error,omitempty"`
	Attempts        int    `json:"attempts"`
	Model           string `json:"model"`
}

// IncidentSummary narrates a group of related alerts.
type IncidentSummary struct {
	Title              string    `json:"title"`
	Severity           string    `json:"severity"`
	Summary            string    `json:"summary"`
	Timeline           []string  `json:"timeline"`
	MITRE              []string  `json:"mitre,omitempty"`
	RecommendedActions []string  `json:"recommended_actions,omitempty"`
	Model              string    `json:"model"`
	CreatedAt          time.Time `json:"created_at"`
}

// Analyst is what the server and CLI use. Implementations must be safe for
// concurrent use.
type Analyst interface {
	Name() string // e.g. "anthropic/claude-opus-5-5"
	Triage(ctx context.Context, in TriageInput) (*Triage, error)
	GenerateRule(ctx context.Context, description string) (*GeneratedRule, error)
	SummarizeIncident(ctx context.Context, host string, alerts []*event.Alert) (*IncidentSummary, error)
}
