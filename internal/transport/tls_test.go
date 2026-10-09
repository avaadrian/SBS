package transport

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/avaadrian/sbs/internal/api"
)

// writeCertPEM PEM-encodes the test server's certificate to a temp file and
// returns its path, for use as a CAFile.
func writeCertPEM(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCAFileTrustAndFetchRules(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != api.PathRules || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(api.RuleSet{Version: "v9", YAML: "- id: X\n  title: t\n"})
	}))
	defer srv.Close()

	// Without the CA the self-signed server is untrusted and the fetch fails.
	bad, err := New(Config{ServerURL: srv.URL, Token: "tok", SpoolDir: t.TempDir(), HTTPTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.FetchRules(context.Background()); err == nil {
		t.Fatal("expected TLS verification failure without CAFile")
	}

	// With the server's CA trusted, the fetch succeeds.
	c, err := New(Config{
		ServerURL: srv.URL, Token: "tok", SpoolDir: t.TempDir(),
		HTTPTimeout: time.Second, CAFile: writeCertPEM(t, srv),
	})
	if err != nil {
		t.Fatal(err)
	}
	rs, err := c.FetchRules(context.Background())
	if err != nil {
		t.Fatalf("FetchRules with CAFile: %v", err)
	}
	if rs.Version != "v9" {
		t.Fatalf("rule set version = %q, want v9", rs.Version)
	}
}

func TestCAFileUnreadableErrors(t *testing.T) {
	_, err := New(Config{
		ServerURL: "https://sbs.example.com", SpoolDir: t.TempDir(),
		CAFile: filepath.Join(t.TempDir(), "does-not-exist.pem"),
	})
	if err == nil {
		t.Fatal("expected New to error on an unreadable CAFile")
	}
}

func TestCAFileNoCertsErrors(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{ServerURL: "https://sbs.example.com", SpoolDir: t.TempDir(), CAFile: empty})
	if err == nil {
		t.Fatal("expected New to error when the CAFile has no certificates")
	}
}
