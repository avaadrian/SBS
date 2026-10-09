package llm

import "regexp"

// redactPlaceholder replaces any value Redact masks.
const redactPlaceholder = "[REDACTED]"

// Redactors run in order: the most specific patterns first so that a value
// matched by, say, the password= rule is masked before the generic long-blob
// rule would see it. Each entry either masks its whole match or, when it has a
// replace function, keeps a leading prefix (e.g. "password=") and masks the
// rest.
var redactors = []struct {
	re      *regexp.Regexp
	replace func(groups []string) string // nil means mask the whole match
}{
	// PEM private key blocks (any key type), spanning multiple lines.
	{re: regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)},
	// key=value / key: value secrets: keep the key and separator, mask the value.
	{
		re: regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|client[_-]?secret)(\s*[=:]\s*)(["']?)([^\s"'&;,]+)`),
		replace: func(g []string) string {
			return g[1] + g[2] + g[3] + redactPlaceholder
		},
	},
	// Authorization headers: keep the header name, mask the rest of the line.
	{
		re: regexp.MustCompile(`(?im)(authorization\s*:\s*)(\S[^\n]*)`),
		replace: func(g []string) string {
			return g[1] + redactPlaceholder
		},
	},
	// Standalone bearer tokens.
	{
		re: regexp.MustCompile(`(?i)\b(bearer\s+)([A-Za-z0-9._~+/\-]{6,}=*)`),
		replace: func(g []string) string {
			return g[1] + redactPlaceholder
		},
	},
	// AWS-style access key IDs (AKIA, ASIA, AROA, ...).
	{re: regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b`)},
	// Anthropic API keys.
	{re: regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{10,}`)},
	// Other sk- style provider keys.
	{re: regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`)},
	// Long hex blobs that look like hashes or keys.
	{re: regexp.MustCompile(`\b[0-9a-fA-F]{40,}\b`)},
	// Long base64-ish blobs that look like keys (keep the leading boundary char).
	{
		re: regexp.MustCompile(`(^|[^A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})`),
		replace: func(g []string) string {
			return g[1] + redactPlaceholder
		},
	},
}

// Redact masks likely secrets in an attacker- or host-controlled string before
// it is sent to the model. It returns the redacted string and the number of
// substitutions made.
func Redact(s string) (string, int) {
	count := 0
	for _, r := range redactors {
		re := r.re
		replace := r.replace
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			count++
			if replace == nil {
				return redactPlaceholder
			}
			return replace(re.FindStringSubmatch(m))
		})
	}
	return s, count
}
