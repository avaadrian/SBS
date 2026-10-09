package llm

import (
	"fmt"
	"time"
)

// Providers.
const (
	ProviderOff       = "off"
	ProviderOllama    = "ollama"    // local model, keeps data on the host (default)
	ProviderAnthropic = "anthropic" // Claude API
)

// Config selects and configures an analyst provider for the server and CLI.
type Config struct {
	Provider  string        `yaml:"provider"`   // off | ollama | anthropic
	Model     string        `yaml:"model"`      // provider-specific; empty = provider default
	BaseURL   string        `yaml:"base_url"`   // Ollama server URL, or Anthropic base URL override
	APIKey    string        `yaml:"api_key"`    // Anthropic only; falls back to ANTHROPIC_API_KEY
	MaxTokens int           `yaml:"max_tokens"` // response cap
	Timeout   time.Duration `yaml:"timeout"`
}

// New builds an Analyst from cfg. For ProviderOff it returns (nil, nil): AI
// analysis is simply unavailable, which callers treat as optional. ErrDisabled
// is returned only when a provider was selected but cannot be initialized
// (e.g. Anthropic without a key).
func New(cfg Config) (Analyst, error) {
	switch cfg.Provider {
	case "", ProviderOff:
		return nil, nil
	case ProviderOllama:
		return NewOllama(OllamaConfig{
			BaseURL: cfg.BaseURL, Model: cfg.Model, MaxTokens: cfg.MaxTokens, Timeout: cfg.Timeout,
		})
	case ProviderAnthropic:
		return NewAnthropic(AnthropicConfig{
			APIKey: cfg.APIKey, BaseURL: cfg.BaseURL, Model: cfg.Model,
			MaxTokens: int64(cfg.MaxTokens), Timeout: cfg.Timeout,
		})
	default:
		return nil, fmt.Errorf("llm: unknown provider %q", cfg.Provider)
	}
}
