package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/avaadrian/sbs/internal/event"
	"github.com/avaadrian/sbs/internal/store"
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

// TestApprovalFlow covers the ask-mode approval endpoints: a proposed alert is
// listed as pending, approving enqueues the derived command and marks it
// approved, and declining dismisses it.
func TestApprovalFlow(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := New(st, Config{})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	host := hostFixture()
	if err := st.UpsertHost(host); err != nil {
		t.Fatal(err)
	}
	a := mkAlert("a1", "critical")
	a.Proposed = []string{"kill"} // agent proposed, awaiting approval
	if _, _, err := st.InsertAlerts(host.ID, []*event.Alert{a}); err != nil {
		t.Fatal(err)
	}

	// It shows up as a pending approval.
	pend, err := st.ListPendingApprovals(10)
	if err != nil || len(pend) != 1 {
		t.Fatalf("pending approvals = %d (%v)", len(pend), err)
	}

	// Approve → 200, a kill command is enqueued for the host, status approved.
	resp := post(t, ts.URL+"/api/alerts/a1/approve", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve = %d", resp.StatusCode)
	}
	cmds, err := st.PendingCommands(host.ID)
	if err != nil || len(cmds) != 1 || cmds[0].Type != "kill" || cmds[0].PID != 4121 {
		t.Fatalf("expected one kill command for pid 4121, got %+v (%v)", cmds, err)
	}
	got, _ := st.GetAlert("a1")
	if got.Approval != store.ApprovalApproved {
		t.Fatalf("approval = %q, want approved", got.Approval)
	}
	if n, _ := st.ListPendingApprovals(10); len(n) != 0 {
		t.Fatalf("still pending after approve: %d", len(n))
	}
}
