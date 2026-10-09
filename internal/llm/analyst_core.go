package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/avaadrian/sbs/internal/event"
	"github.com/avaadrian/sbs/internal/rules"
)

// maxRuleAttempts is the number of rule generations (one initial plus repairs).
const maxRuleAttempts = 3

// completer is the provider-specific half of an analyst: a single system+user
// exchange returning text and token usage. The triage/rule/incident
// orchestration in core is shared across providers (Anthropic, Ollama).
type completer interface {
	complete(ctx context.Context, system, user string) (text string, in, out int64, err error)
	name() string    // provider/model, e.g. "anthropic/claude-opus-5-5"
	modelID() string // bare model id recorded on results
}

// core implements Analyst on top of any completer.
type core struct{ c completer }

// Name returns the provider and model.
func (a *core) Name() string { return a.c.name() }

// completeJSON sends system+user, extracts the first balanced JSON object from
// the reply and unmarshals it into dst. On a parse failure it performs one
// repair retry that feeds back the previous output and the error. Token usage
// is summed across both calls.
func (a *core) completeJSON(ctx context.Context, system, user string, dst any) (in, out int64, err error) {
	text, in, out, err := a.c.complete(ctx, system, user)
	if err != nil {
		return in, out, err
	}
	if parseErr := parseJSONObject(text, dst); parseErr == nil {
		return in, out, nil
	} else {
		text2, in2, out2, rerr := a.c.complete(ctx, system, buildRepairUser(text, parseErr.Error()))
		in += in2
		out += out2
		if rerr != nil {
			return in, out, rerr
		}
		if err := parseJSONObject(text2, dst); err != nil {
			return in, out, fmt.Errorf("llm: parse model output: %w", err)
		}
		return in, out, nil
	}
}

// parseJSONObject extracts the first balanced JSON object from s and unmarshals
// it into dst.
func parseJSONObject(s string, dst any) error {
	raw, err := extractJSONObject(s)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(raw), dst)
}

// extractJSONObject returns the first balanced {...} object in s, ignoring any
// surrounding prose or markdown fences and braces inside string literals.
func extractJSONObject(s string) (string, error) {
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return "", fmt.Errorf("no JSON object in model output")
	}
	depth, inStr, esc := 0, false, false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1], nil
			}
		}
	}
	return "", fmt.Errorf("unbalanced JSON object in model output")
}

// triageJSON mirrors the JSON shape the model is asked to return for triage.
type triageJSON struct {
	Verdict            string   `json:"verdict"`
	Confidence         float64  `json:"confidence"`
	Severity           string   `json:"severity"`
	Summary            string   `json:"summary"`
	Analysis           string   `json:"analysis"`
	MITRE              []string `json:"mitre"`
	RecommendedActions []string `json:"recommended_actions"`
}

// Triage assesses a single alert.
func (a *core) Triage(ctx context.Context, in TriageInput) (*Triage, error) {
	if in.Alert == nil {
		return nil, fmt.Errorf("llm: triage: nil alert")
	}
	user, redactions := buildTriageUser(in)
	var raw triageJSON
	inTok, outTok, err := a.completeJSON(ctx, triageSystemPrompt, user, &raw)
	if err != nil {
		return nil, err
	}
	t := &Triage{
		Verdict:            raw.Verdict,
		Confidence:         raw.Confidence,
		Severity:           raw.Severity,
		Summary:            raw.Summary,
		Analysis:           raw.Analysis,
		MITRE:              raw.MITRE,
		RecommendedActions: raw.RecommendedActions,
		Model:              a.c.modelID(),
		InputTokens:        int(inTok),
		OutputTokens:       int(outTok),
		Redactions:         redactions,
		CreatedAt:          time.Now().UTC(),
	}
	if t.Confidence < 0 {
		t.Confidence = 0
	} else if t.Confidence > 1 {
		t.Confidence = 1
	}
	if !allowedVerdicts[t.Verdict] {
		t.Verdict = VerdictUnknown
	}
	if !allowedSeverities[t.Severity] {
		t.Severity = "medium"
	}
	return t, nil
}

// ruleJSON mirrors the JSON envelope the model returns for rule generation.
type ruleJSON struct {
	YAML        string `json:"yaml"`
	Explanation string `json:"explanation"`
}

// GenerateRule writes a detection rule from a description and validates it with
// the rule engine, retrying up to maxRuleAttempts times when validation fails.
func (a *core) GenerateRule(ctx context.Context, description string) (*GeneratedRule, error) {
	gr := &GeneratedRule{Model: a.c.modelID()}
	user := buildRuleUser(description)
	for attempt := 1; attempt <= maxRuleAttempts; attempt++ {
		gr.Attempts = attempt
		var raw ruleJSON
		_, _, err := a.completeJSON(ctx, ruleSystemPrompt, user, &raw)
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			gr.Valid = false
			gr.ValidationError = err.Error()
			if attempt < maxRuleAttempts {
				// The reply could not be parsed as the required JSON, so there is
				// no candidate YAML to repair: re-ask from the description with
				// the parse error as feedback rather than referencing stale YAML.
				user = buildRuleUser(description) +
					"\n\nYour previous reply could not be parsed (" + err.Error() +
					"). Return ONLY the JSON object described above."
				continue
			}
			return gr, nil
		}
		gr.YAML = raw.YAML
		gr.Explanation = raw.Explanation
		if _, perr := rules.Parse([]byte(raw.YAML), "generated"); perr == nil {
			gr.Valid = true
			gr.ValidationError = ""
			return gr, nil
		} else {
			gr.Valid = false
			gr.ValidationError = perr.Error()
			if attempt < maxRuleAttempts {
				user = buildRuleRepairUser(raw.YAML, perr.Error())
			}
		}
	}
	return gr, nil
}

// incidentJSON mirrors the JSON shape the model returns for incident summaries.
type incidentJSON struct {
	Title              string   `json:"title"`
	Severity           string   `json:"severity"`
	Summary            string   `json:"summary"`
	Timeline           []string `json:"timeline"`
	MITRE              []string `json:"mitre"`
	RecommendedActions []string `json:"recommended_actions"`
}

// SummarizeIncident narrates a group of related alerts.
func (a *core) SummarizeIncident(ctx context.Context, host string, alerts []*event.Alert) (*IncidentSummary, error) {
	if len(alerts) == 0 {
		return nil, fmt.Errorf("llm: summarize: no alerts")
	}
	user, _ := buildIncidentUser(host, alerts)
	var raw incidentJSON
	if _, _, err := a.completeJSON(ctx, incidentSystemPrompt, user, &raw); err != nil {
		return nil, err
	}
	is := &IncidentSummary{
		Title:              raw.Title,
		Severity:           raw.Severity,
		Summary:            raw.Summary,
		Timeline:           raw.Timeline,
		MITRE:              raw.MITRE,
		RecommendedActions: raw.RecommendedActions,
		Model:              a.c.modelID(),
		CreatedAt:          time.Now().UTC(),
	}
	if !allowedSeverities[is.Severity] {
		is.Severity = "medium"
	}
	return is, nil
}
