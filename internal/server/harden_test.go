package server

import (
	"bytes"
	"net/http"
	"testing"
)

// TestConsoleCSRFGuard verifies state-changing console POSTs reject cross-site
// browser requests and non-JSON command bodies.
func TestConsoleCSRFGuard(t *testing.T) {
	ts := newTestServer(t, Config{})
	cmdURL := ts.URL + "/api/hosts/host-1/commands"

	// Cross-site browser request (Sec-Fetch-Site: cross-site) → 403.
	req, _ := http.NewRequest(http.MethodPost, cmdURL, bytes.NewReader([]byte(`{"type":"scan","path":"/tmp"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site POST = %d, want 403", resp.StatusCode)
	}

	// Non-JSON content type (CSRF "simple request") → 415.
	req, _ = http.NewRequest(http.MethodPost, cmdURL, bytes.NewReader([]byte(`{"type":"scan","path":"/tmp"}`)))
	req.Header.Set("Content-Type", "text/plain")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain POST = %d, want 415", resp.StatusCode)
	}

	// Same-origin JSON request is allowed through the guard (reaches handler).
	req, _ = http.NewRequest(http.MethodPost, cmdURL, bytes.NewReader([]byte(`{"type":"scan","path":"/tmp"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnsupportedMediaType {
		t.Errorf("same-origin JSON POST wrongly rejected: %d", resp.StatusCode)
	}
}
