package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DefaultOllamaModel is used when OllamaConfig.Model is empty.
const DefaultOllamaModel = "llama3.1"

// DefaultOllamaURL is the local Ollama server address.
const DefaultOllamaURL = "http://localhost:11434"

// OllamaConfig configures a local Ollama-backed analyst. Running the model
// locally keeps event data on the host — nothing leaves the machine.
type OllamaConfig struct {
	BaseURL   string        // defaults to DefaultOllamaURL
	Model     string        // defaults to DefaultOllamaModel
	MaxTokens int           // num_predict; <=0 means the server default
	Timeout   time.Duration // per-request timeout (default 120s — local models are slower)
}

// ollamaCompleter talks to a local Ollama server's /api/chat endpoint.
type ollamaCompleter struct {
	base      string
	model     string
	maxTokens int
	http      *http.Client
}

// NewOllama builds an Ollama-backed Analyst. It does not probe the server, so
// construction always succeeds; a request fails if the server is unreachable.
func NewOllama(cfg OllamaConfig) (Analyst, error) {
	base := cfg.BaseURL
	if base == "" {
		base = DefaultOllamaURL
	}
	model := cfg.Model
	if model == "" {
		model = DefaultOllamaModel
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &core{c: &ollamaCompleter{
		base:      strings.TrimRight(base, "/"),
		model:     model,
		maxTokens: cfg.MaxTokens,
		http:      &http.Client{Timeout: timeout},
	}}, nil
}

func (o *ollamaCompleter) name() string    { return "ollama/" + o.model }
func (o *ollamaCompleter) modelID() string { return o.model }

type ollamaChatRequest struct {
	Model    string              `json:"model"`
	Messages []ollamaChatMessage `json:"messages"`
	Stream   bool                `json:"stream"`
	Format   string              `json:"format"` // "json" forces a JSON object reply
	Options  ollamaOptions       `json:"options"`
}

type ollamaChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaOptions struct {
	Temperature float64 `json:"temperature"`
	NumPredict  int     `json:"num_predict,omitempty"`
}

type ollamaChatResponse struct {
	Message         ollamaChatMessage `json:"message"`
	PromptEvalCount int               `json:"prompt_eval_count"`
	EvalCount       int               `json:"eval_count"`
	Error           string            `json:"error"`
}

// complete sends one system+user exchange to Ollama with JSON-mode output and
// deterministic sampling.
func (o *ollamaCompleter) complete(ctx context.Context, system, user string) (text string, in, out int64, err error) {
	reqBody, err := json.Marshal(ollamaChatRequest{
		Model: o.model,
		Messages: []ollamaChatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Stream:  false,
		Format:  "json",
		Options: ollamaOptions{Temperature: 0, NumPredict: o.maxTokens},
	})
	if err != nil {
		return "", 0, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.base+"/api/chat", bytes.NewReader(reqBody))
	if err != nil {
		return "", 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.http.Do(req)
	if err != nil {
		return "", 0, 0, fmt.Errorf("llm: ollama request: %w", err)
	}
	defer resp.Body.Close()
	var cr ollamaChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return "", 0, 0, fmt.Errorf("llm: ollama decode: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if cr.Error != "" {
			return "", 0, 0, fmt.Errorf("llm: ollama: %s", cr.Error)
		}
		return "", 0, 0, fmt.Errorf("llm: ollama: status %d", resp.StatusCode)
	}
	return cr.Message.Content, int64(cr.PromptEvalCount), int64(cr.EvalCount), nil
}
