package llm

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// DefaultModel is the Claude model used when the config does not set one.
const DefaultModel = "claude-opus-5-5"

// defaultMaxTokens keeps responses short: these are small structured replies.
const defaultMaxTokens int64 = 2048

// AnthropicConfig configures the Claude-backed analyst.
type AnthropicConfig struct {
	APIKey    string        // explicit key; falls back to ANTHROPIC_API_KEY
	BaseURL   string        // optional base URL override
	Model     string        // defaults to DefaultModel
	MaxTokens int64         // defaults to defaultMaxTokens
	Timeout   time.Duration // optional per-request timeout
}

// anthropicCompleter talks to the Anthropic Claude API.
type anthropicCompleter struct {
	client    anthropic.Client
	model     string
	maxTokens int64
}

// NewAnthropic builds a Claude-backed Analyst. It returns ErrDisabled when no
// API key is resolvable from the config or the ANTHROPIC_API_KEY environment
// variable.
func NewAnthropic(cfg AnthropicConfig) (Analyst, error) {
	key := cfg.APIKey
	if key == "" {
		key = os.Getenv("ANTHROPIC_API_KEY")
	}
	if key == "" {
		return nil, ErrDisabled
	}
	opts := []option.RequestOption{option.WithAPIKey(key)}
	if cfg.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(cfg.BaseURL))
	}
	if cfg.Timeout > 0 {
		opts = append(opts, option.WithRequestTimeout(cfg.Timeout))
	}
	model := cfg.Model
	if model == "" {
		model = DefaultModel
	}
	maxTokens := cfg.MaxTokens
	if maxTokens <= 0 {
		maxTokens = defaultMaxTokens
	}
	return &core{c: &anthropicCompleter{
		client:    anthropic.NewClient(opts...),
		model:     model,
		maxTokens: maxTokens,
	}}, nil
}

func (a *anthropicCompleter) name() string    { return "anthropic/" + a.model }
func (a *anthropicCompleter) modelID() string { return a.model }

// complete sends one system+user exchange and returns the concatenated text
// content plus token usage. Thinking blocks are read and discarded; only the
// text blocks carry the structured answer.
func (a *anthropicCompleter) complete(ctx context.Context, system, user string) (text string, in, out int64, err error) {
	adaptive := anthropic.ThinkingConfigAdaptiveParam{}
	resp, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(a.model),
		MaxTokens: a.maxTokens,
		Thinking:  anthropic.ThinkingConfigParamUnion{OfAdaptive: &adaptive},
		System:    []anthropic.TextBlockParam{{Text: system}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(user)),
		},
	})
	if err != nil {
		return "", 0, 0, fmt.Errorf("llm: anthropic request: %w", err)
	}
	var sb strings.Builder
	for _, block := range resp.Content {
		switch b := block.AsAny().(type) {
		case anthropic.ThinkingBlock:
			// reasoning is not part of the structured answer; ignore it
		case anthropic.TextBlock:
			sb.WriteString(b.Text)
		}
	}
	return sb.String(), resp.Usage.InputTokens, resp.Usage.OutputTokens, nil
}
