package llm

import (
	"strings"
	"testing"
)

func TestRedactMasksSecrets(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		secret string // a substring that must NOT survive
	}{
		{"aws", "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"},
		{"anthropic", "key is sk-ant-api03-abcDEF123456_the-rest", "sk-ant-api03-abcDEF123456_the-rest"},
		{"openai", "token sk-proj0123456789ABCDEFGHIJ hanging around", "sk-proj0123456789ABCDEFGHIJ"},
		{"bearer", "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1Ni9999'", "eyJhbGciOiJIUzI1Ni9999"},
		{"password", "mysql -u root --password=hunter2secret db", "hunter2secret"},
		{"apikey", "api_key=deadBEEF01234567 next", "deadBEEF01234567"},
		{"hex", "sha is " + strings.Repeat("a1", 24), strings.Repeat("a1", 24)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, n := Redact(c.in)
			if n == 0 {
				t.Fatalf("expected at least one redaction, got 0 for %q", c.in)
			}
			if strings.Contains(out, c.secret) {
				t.Fatalf("secret survived redaction: %q still in %q", c.secret, out)
			}
			if !strings.Contains(out, redactPlaceholder) {
				t.Fatalf("expected placeholder in output, got %q", out)
			}
		})
	}
}

func TestRedactPEMBlock(t *testing.T) {
	in := "leaked:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAbogus\nlines\n-----END RSA PRIVATE KEY-----\ndone"
	out, n := Redact(in)
	if n != 1 {
		t.Fatalf("expected 1 redaction for PEM block, got %d", n)
	}
	if strings.Contains(out, "BEGIN RSA PRIVATE KEY") || strings.Contains(out, "MIIEpAIBAAKCAQEAbogus") {
		t.Fatalf("PEM block survived: %q", out)
	}
	if !strings.HasPrefix(out, "leaked:") || !strings.HasSuffix(out, "done") {
		t.Fatalf("surrounding text was altered: %q", out)
	}
}

func TestRedactKeepsKeyName(t *testing.T) {
	out, _ := Redact("password=hunter2secret")
	if !strings.HasPrefix(out, "password=") {
		t.Fatalf("expected key name retained, got %q", out)
	}
}

func TestRedactLeavesBenignText(t *testing.T) {
	in := "ran /usr/bin/curl --version and listed /tmp files"
	out, n := Redact(in)
	if n != 0 {
		t.Fatalf("expected no redactions on benign input, got %d (%q)", n, out)
	}
	if out != in {
		t.Fatalf("benign text changed: %q -> %q", in, out)
	}
}
