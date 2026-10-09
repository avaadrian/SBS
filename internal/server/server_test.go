package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/avaadrian/sbs/internal/api"
	"github.com/avaadrian/sbs/internal/event"
	"github.com/avaadrian/sbs/internal/llm"
	"github.com/avaadrian/sbs/internal/store"
)

const testToken = "secret-token"

func mustStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func gzipWriter(w io.Writer) *gzip.Writer { return gzip.NewWriter(w) }

func newTestServer(t *testing.T, cfg Config) *httptest.Server {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	srv := New(st, cfg)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.Wait)
	return ts
}

func post(t *testing.T, url, token string, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

func mkAlert(id, sev string) *event.Alert {
	return &event.Alert{
		ID:       id,
		Time:     time.Now().UTC(),
		RuleID:   "SBS-PROC-003",
		Title:    "reverse shell",
		Severity: sev,
		Event: &event.Event{
			Type:    event.TypeProcess,
			Source:  "netlink",
			Process: &event.Process{PID: 4121, Exe: "/bin/sh", Comm: "sh", Stdin: "inet"},
		},
	}
}

func hostFixture() api.Host {
	return api.Host{ID: "host-1", Hostname: "web01", OS: "Debian 12", Arch: "amd64", ProcessSource: "netlink"}
}

func TestAlertIngestAuth(t *testing.T) {
	ts := newTestServer(t, Config{AgentToken: testToken})

	batch := api.AlertBatch{Host: hostFixture(), Alerts: []*event.Alert{mkAlert("a1", "critical")}}

	// Wrong token -> 401.
	resp := post(t, ts.URL+api.PathAlerts, "wrong", batch)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token: got %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// No token -> 401.
	resp = post(t, ts.URL+api.PathAlerts, "", batch)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Valid token -> 202 with counts.
	resp = post(t, ts.URL+api.PathAlerts, testToken, batch)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("valid token: got %d, want 202", resp.StatusCode)
	}
	var ack api.AlertBatchResponse
	json.NewDecoder(resp.Body).Decode(&ack)
	resp.Body.Close()
	if ack.Accepted != 1 || ack.Duplicate != 0 {
		t.Fatalf("ack: %+v", ack)
	}

	// Re-upload the same batch -> duplicate.
	resp = post(t, ts.URL+api.PathAlerts, testToken, batch)
	json.NewDecoder(resp.Body).Decode(&ack)
	resp.Body.Close()
	if ack.Accepted != 0 || ack.Duplicate != 1 {
		t.Fatalf("dup ack: %+v", ack)
	}

	// Queryable via the console JSON API.
	r, err := http.Get(ts.URL + "/api/alerts")
	if err != nil {
		t.Fatal(err)
	}
	var alerts []*store.Alert
	json.NewDecoder(r.Body).Decode(&alerts)
	r.Body.Close()
	if len(alerts) != 1 || alerts[0].ID != "a1" || alerts[0].Host != "host-1" {
		t.Fatalf("api/alerts: %+v", alerts)
	}

	// And via /api/alerts/{id}.
	r, _ = http.Get(ts.URL + "/api/alerts/a1")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("get alert: %d", r.StatusCode)
	}
	r.Body.Close()
	r, _ = http.Get(ts.URL + "/api/alerts/missing")
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("missing alert: %d", r.StatusCode)
	}
	r.Body.Close()
}

func TestHeartbeatCommandFlow(t *testing.T) {
	ts := newTestServer(t, Config{AgentToken: testToken})

	// Console enqueues a kill command for host-1.
	cmdReq := map[string]any{"type": api.CmdKill, "pid": 4121, "reason": "reverse shell"}
	resp := post(t, ts.URL+"/api/hosts/host-1/commands", "", cmdReq)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("enqueue: got %d, want 201", resp.StatusCode)
	}
	var queued api.Command
	json.NewDecoder(resp.Body).Decode(&queued)
	resp.Body.Close()
	if queued.ID == "" || queued.Type != api.CmdKill || queued.PID != 4121 {
		t.Fatalf("queued command: %+v", queued)
	}

	// Heartbeat returns the pending command.
	hb := api.Heartbeat{Host: hostFixture(), Time: time.Now().UTC()}
	resp = post(t, ts.URL+api.PathHeartbeat, testToken, hb)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat: got %d, want 200", resp.StatusCode)
	}
	var hbr api.HeartbeatResponse
	json.NewDecoder(resp.Body).Decode(&hbr)
	resp.Body.Close()
	if len(hbr.Commands) != 1 || hbr.Commands[0].ID != queued.ID {
		t.Fatalf("heartbeat commands: %+v", hbr.Commands)
	}

	// A second heartbeat sees nothing (command was marked sent). Decode into a
	// fresh value: Commands is omitempty, so an empty response omits the key.
	resp = post(t, ts.URL+api.PathHeartbeat, testToken, hb)
	var hbr2 api.HeartbeatResponse
	json.NewDecoder(resp.Body).Decode(&hbr2)
	resp.Body.Close()
	if len(hbr2.Commands) != 0 {
		t.Fatalf("command re-delivered: %+v", hbr2.Commands)
	}

	// Agent reports the result -> 204.
	res := api.CommandResult{HostID: "host-1", CommandID: queued.ID, OK: true, Output: "killed", Time: time.Now().UTC()}
	resp = post(t, ts.URL+api.PathCommandResult, testToken, res)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("command result: got %d, want 204", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestEnqueueCommandValidation(t *testing.T) {
	ts := newTestServer(t, Config{AgentToken: testToken})
	cases := []map[string]any{
		{"type": "bogus"},
		{"type": api.CmdKill},       // missing pid
		{"type": api.CmdQuarantine}, // missing path
	}
	for _, c := range cases {
		resp := post(t, ts.URL+"/api/hosts/host-1/commands", "", c)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("case %+v: got %d, want 400", c, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestGzipIngest(t *testing.T) {
	ts := newTestServer(t, Config{AgentToken: testToken})
	batch := api.AlertBatch{Host: hostFixture(), Alerts: []*event.Alert{mkAlert("gz1", "high")}}
	raw, _ := json.Marshal(batch)
	var buf bytes.Buffer
	gz := gzipWriter(&buf)
	gz.Write(raw)
	gz.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+api.PathAlerts, &buf)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("gzip ingest: got %d (%s)", resp.StatusCode, b)
	}
	resp.Body.Close()
}

// fakeAnalyst returns a canned triage and satisfies the llm.Analyst interface.
type fakeAnalyst struct{ calls int }

func (f *fakeAnalyst) Name() string { return "fake/test" }
func (f *fakeAnalyst) Triage(ctx context.Context, in llm.TriageInput) (*llm.Triage, error) {
	f.calls++
	return &llm.Triage{
		Verdict:    llm.VerdictMalicious,
		Confidence: 0.92,
		Severity:   "critical",
		Summary:    "reverse shell to attacker",
		Model:      "fake/test",
		CreatedAt:  time.Now().UTC(),
	}, nil
}
func (f *fakeAnalyst) GenerateRule(ctx context.Context, description string) (*llm.GeneratedRule, error) {
	return &llm.GeneratedRule{Valid: true}, nil
}
func (f *fakeAnalyst) SummarizeIncident(ctx context.Context, host string, alerts []*event.Alert) (*llm.IncidentSummary, error) {
	return &llm.IncidentSummary{Title: "incident"}, nil
}

func TestTriageEndpointNoAnalyst(t *testing.T) {
	ts := newTestServer(t, Config{AgentToken: testToken})
	post2 := post(t, ts.URL+api.PathAlerts, testToken,
		api.AlertBatch{Host: hostFixture(), Alerts: []*event.Alert{mkAlert("a1", "high")}})
	post2.Body.Close()

	resp := post(t, ts.URL+"/api/alerts/a1/triage", "", nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("triage without analyst: got %d, want 503", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestTriageEndpointWithAnalyst(t *testing.T) {
	fa := &fakeAnalyst{}
	ts := newTestServer(t, Config{AgentToken: testToken, Analyst: fa})

	// Ingest an alert (AutoTriageMinSeverity unset -> no auto-triage).
	resp := post(t, ts.URL+api.PathAlerts, testToken,
		api.AlertBatch{Host: hostFixture(), Alerts: []*event.Alert{mkAlert("a1", "critical")}})
	resp.Body.Close()

	// On-demand triage returns and persists the verdict.
	resp = post(t, ts.URL+"/api/alerts/a1/triage", "", nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("triage: got %d (%s)", resp.StatusCode, b)
	}
	var tr llm.Triage
	json.NewDecoder(resp.Body).Decode(&tr)
	resp.Body.Close()
	if tr.Verdict != llm.VerdictMalicious {
		t.Fatalf("triage verdict: %+v", tr)
	}
	if fa.calls == 0 {
		t.Fatal("analyst was not called")
	}

	// Triage is now stored on the alert.
	r, _ := http.Get(ts.URL + "/api/alerts/a1")
	var got store.Alert
	json.NewDecoder(r.Body).Decode(&got)
	r.Body.Close()
	if len(got.Triage) == 0 {
		t.Fatal("triage not persisted on alert")
	}
	if !strings.Contains(string(got.Triage), "malicious") {
		t.Fatalf("stored triage: %s", got.Triage)
	}
}

func TestAutoTriageOnIngest(t *testing.T) {
	fa := &fakeAnalyst{}
	srv := New(mustStore(t), Config{AgentToken: testToken, Analyst: fa, AutoTriageMinSeverity: "high"})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// A low-severity alert must NOT be auto-triaged; a critical one must.
	resp := post(t, ts.URL+api.PathAlerts, testToken, api.AlertBatch{
		Host:   hostFixture(),
		Alerts: []*event.Alert{mkAlert("low1", "low"), mkAlert("crit1", "critical")},
	})
	resp.Body.Close()

	srv.Wait() // wait for background triage to finish

	if fa.calls != 1 {
		t.Fatalf("auto-triage calls: got %d, want 1 (only the critical alert)", fa.calls)
	}
	r, _ := http.Get(ts.URL + "/api/alerts/crit1")
	var crit store.Alert
	json.NewDecoder(r.Body).Decode(&crit)
	r.Body.Close()
	if len(crit.Triage) == 0 {
		t.Fatal("critical alert was not auto-triaged")
	}
	r, _ = http.Get(ts.URL + "/api/alerts/low1")
	var low store.Alert
	json.NewDecoder(r.Body).Decode(&low)
	r.Body.Close()
	if len(low.Triage) != 0 {
		t.Fatal("low alert should not have been auto-triaged")
	}
}

func TestDashboardRenders(t *testing.T) {
	ts := newTestServer(t, Config{AgentToken: testToken})
	r, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("dashboard: %d", r.StatusCode)
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("dashboard content-type: %q", ct)
	}
	body := string(mustRead(r.Body))
	if !strings.Contains(body, "SBS Console") {
		t.Fatal("dashboard missing title")
	}
	if strings.Contains(body, "{{") {
		t.Fatal("dashboard template was not rendered (raw actions present)")
	}
	// Template values are injected; whitespace around JS values varies.
	norm := strings.Join(strings.Fields(body), " ")
	if !strings.Contains(norm, "aiEnabled: false") {
		t.Fatal("dashboard config (aiEnabled) not injected")
	}
}

func mustRead(r io.Reader) []byte {
	b, _ := io.ReadAll(r)
	return b
}
