package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/avaadrian/sbs/internal/api"
	"github.com/avaadrian/sbs/internal/event"
	"github.com/avaadrian/sbs/internal/llm"
	"github.com/avaadrian/sbs/internal/store"
)

const consoleToken = "console-secret"

// getWith issues a GET with an optional bearer token and/or session cookie.
func getWith(t *testing.T, url, bearer string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

// sessionCookieOf returns the sbs_session cookie from a response, or nil.
func sessionCookieOf(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	return nil
}

func TestLoginLogoutSession(t *testing.T) {
	ts := newTestServer(t, Config{AgentToken: testToken, ConsoleToken: consoleToken})

	// /api/session needs no auth and reports auth is required.
	resp := getWith(t, ts.URL+"/api/session", "", nil)
	var sess struct {
		AuthRequired  bool `json:"auth_required"`
		Authenticated bool `json:"authenticated"`
		AI            struct {
			Enabled  bool   `json:"enabled"`
			Provider string `json:"provider"`
		} `json:"ai"`
	}
	json.NewDecoder(resp.Body).Decode(&sess)
	resp.Body.Close()
	if !sess.AuthRequired || sess.Authenticated || sess.AI.Enabled {
		t.Fatalf("session (pre-login): %+v", sess)
	}

	// Bad token -> 401.
	resp = post(t, ts.URL+"/api/login", "", map[string]string{"token": "nope"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login: got %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Good token -> 204 + session cookie.
	resp = post(t, ts.URL+"/api/login", "", map[string]string{"token": consoleToken})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("login: got %d, want 204", resp.StatusCode)
	}
	cookie := sessionCookieOf(resp)
	resp.Body.Close()
	if cookie == nil || cookie.Value == "" {
		t.Fatal("login did not set a session cookie")
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie flags: HttpOnly=%v SameSite=%v", cookie.HttpOnly, cookie.SameSite)
	}
	if cookie.Secure {
		t.Fatal("session cookie should not be Secure without TLS")
	}

	// The cookie now authenticates /api/session.
	resp = getWith(t, ts.URL+"/api/session", "", cookie)
	json.NewDecoder(resp.Body).Decode(&sess)
	resp.Body.Close()
	if !sess.Authenticated {
		t.Fatal("session with cookie not authenticated")
	}

	// Logout clears the session (cookie no longer authenticates).
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/logout", nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: got %d, want 204", resp.StatusCode)
	}
	resp.Body.Close()

	resp = getWith(t, ts.URL+"/api/session", "", cookie)
	json.NewDecoder(resp.Body).Decode(&sess)
	resp.Body.Close()
	if sess.Authenticated {
		t.Fatal("session still authenticated after logout")
	}
}

func TestLoginRateLimit(t *testing.T) {
	ts := newTestServer(t, Config{ConsoleToken: consoleToken})
	// Five failures are allowed (401); the sixth is blocked (429).
	for i := 0; i < loginMaxFails; i++ {
		resp := post(t, ts.URL+"/api/login", "", map[string]string{"token": "wrong"})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i, resp.StatusCode)
		}
		resp.Body.Close()
	}
	resp := post(t, ts.URL+"/api/login", "", map[string]string{"token": "wrong"})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("rate-limited attempt: got %d, want 429", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestConsoleAuthMiddleware(t *testing.T) {
	ts := newTestServer(t, Config{AgentToken: testToken, ConsoleToken: consoleToken})

	// No auth -> 401 with the documented error body.
	resp := getWith(t, ts.URL+"/api/rules", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no auth: got %d, want 401", resp.StatusCode)
	}
	var e struct {
		Error string `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&e)
	resp.Body.Close()
	if e.Error != "login required" {
		t.Fatalf("401 body: %q", e.Error)
	}

	// Bearer console token -> allowed.
	resp = getWith(t, ts.URL+"/api/rules", consoleToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bearer: got %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// Session cookie -> allowed.
	lr := post(t, ts.URL+"/api/login", "", map[string]string{"token": consoleToken})
	cookie := sessionCookieOf(lr)
	lr.Body.Close()
	resp = getWith(t, ts.URL+"/api/rules", "", cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cookie: got %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestModeRoundTrip(t *testing.T) {
	ts := newTestServer(t, Config{AgentToken: testToken}) // open console

	// Agent heartbeat registers the host.
	hb := api.Heartbeat{Host: hostFixture()}
	resp := post(t, ts.URL+api.PathHeartbeat, testToken, hb)
	resp.Body.Close()

	// Operator sets auto mode.
	resp = post(t, ts.URL+"/api/hosts/host-1/mode", "", map[string]string{"mode": "auto"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set mode: got %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// An unknown mode is rejected.
	resp = post(t, ts.URL+"/api/hosts/host-1/mode", "", map[string]string{"mode": "bogus"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad mode: got %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// Setting mode on an unknown host -> 404.
	resp = post(t, ts.URL+"/api/hosts/ghost/mode", "", map[string]string{"mode": "ask"})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("mode on unknown host: got %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()

	// It surfaces in the overview as the host's desired_mode.
	resp = getWith(t, ts.URL+"/api/overview", "", nil)
	var ov struct {
		Hosts []struct {
			ID          string `json:"id"`
			DesiredMode string `json:"desired_mode"`
		} `json:"hosts"`
	}
	json.NewDecoder(resp.Body).Decode(&ov)
	resp.Body.Close()
	if len(ov.Hosts) != 1 || ov.Hosts[0].DesiredMode != "auto" {
		t.Fatalf("overview desired_mode: %+v", ov.Hosts)
	}

	// And it is delivered to the agent in the heartbeat response.
	resp = post(t, ts.URL+api.PathHeartbeat, testToken, hb)
	var hbr api.HeartbeatResponse
	json.NewDecoder(resp.Body).Decode(&hbr)
	resp.Body.Close()
	if hbr.ResponseMode != "auto" {
		t.Fatalf("heartbeat ResponseMode: %q, want auto", hbr.ResponseMode)
	}

	// Clearing the override removes it.
	resp = post(t, ts.URL+"/api/hosts/host-1/mode", "", map[string]string{"mode": ""})
	resp.Body.Close()
	resp = post(t, ts.URL+api.PathHeartbeat, testToken, hb)
	hbr = api.HeartbeatResponse{}
	json.NewDecoder(resp.Body).Decode(&hbr)
	resp.Body.Close()
	if hbr.ResponseMode != "" {
		t.Fatalf("heartbeat ResponseMode after clear: %q, want empty", hbr.ResponseMode)
	}
}

const validRuleYAML = `- id: CUSTOM-001
  title: Suspicious binary executed
  severity: high
  event: process
  match:
    field: process.exe
    op: equals
    value: /tmp/evil`

func createRule(t *testing.T, url, yaml, source string) *http.Response {
	t.Helper()
	return post(t, url, "", map[string]string{"yaml": yaml, "source": source})
}

// rulesVersionNow reads the current rule-set version from GET /api/rules.
func rulesVersionNow(t *testing.T, url string) string {
	t.Helper()
	resp := getWith(t, url+"/api/rules", "", nil)
	var body struct {
		Version string             `json:"version"`
		Rules   []store.CustomRule `json:"rules"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	return body.Version
}

func TestCustomRulesLifecycle(t *testing.T) {
	ts := newTestServer(t, Config{AgentToken: testToken}) // open console

	emptyVersion := rulesVersionNow(t, ts.URL)
	if emptyVersion == "" {
		t.Fatal("empty rule set should still have a version")
	}

	// Add a valid rule -> 201.
	resp := createRule(t, ts.URL+"/api/rules", validRuleYAML, "manual")
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create rule: got %d (%s)", resp.StatusCode, b)
	}
	var cr store.CustomRule
	json.NewDecoder(resp.Body).Decode(&cr)
	resp.Body.Close()
	if cr.ID == "" || cr.RuleID != "CUSTOM-001" || cr.Severity != "high" || cr.Event != "process" || !cr.Enabled {
		t.Fatalf("created rule: %+v", cr)
	}

	// The version changed now that a rule is enabled.
	v1 := rulesVersionNow(t, ts.URL)
	if v1 == emptyVersion {
		t.Fatal("version did not change after adding a rule")
	}

	// Invalid rule (valid YAML, no event) -> 400.
	resp = createRule(t, ts.URL+"/api/rules", "- id: BAD-1\n  title: no event", "manual")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid rule: got %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// More than one rule -> 400.
	resp = createRule(t, ts.URL+"/api/rules", validRuleYAML+"\n- id: CUSTOM-002\n  title: x\n  event: file\n  match:\n    field: file.path\n    op: equals\n    value: /x", "manual")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("two rules: got %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// Duplicate rule_id -> 400.
	resp = createRule(t, ts.URL+"/api/rules", validRuleYAML, "manual")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("duplicate rule: got %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// Agent rules endpoint returns the enabled YAML and matching version.
	resp = getWith(t, ts.URL+api.PathRules, testToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("agent rules: got %d, want 200", resp.StatusCode)
	}
	var rs api.RuleSet
	json.NewDecoder(resp.Body).Decode(&rs)
	resp.Body.Close()
	if rs.Version != v1 {
		t.Fatalf("agent rule-set version %q != console version %q", rs.Version, v1)
	}
	if !strings.Contains(rs.YAML, "CUSTOM-001") || !strings.Contains(rs.YAML, "/tmp/evil") {
		t.Fatalf("agent rule YAML missing content: %q", rs.YAML)
	}

	// Disabling the rule changes the version and empties the served YAML.
	resp = post(t, ts.URL+"/api/rules/"+cr.ID+"/enabled", "", map[string]bool{"enabled": false})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disable rule: got %d, want 200", resp.StatusCode)
	}
	var disabled store.CustomRule
	json.NewDecoder(resp.Body).Decode(&disabled)
	resp.Body.Close()
	if disabled.Enabled {
		t.Fatal("rule still enabled after disable")
	}
	if v2 := rulesVersionNow(t, ts.URL); v2 != emptyVersion {
		t.Fatalf("version after disabling only rule %q, want empty-set version %q", v2, emptyVersion)
	}

	// Delete -> 204, then 404 on a second delete.
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/rules/"+cr.ID, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete rule: got %d, want 204", resp.StatusCode)
	}
	resp.Body.Close()
	req, _ = http.NewRequest(http.MethodDelete, ts.URL+"/api/rules/"+cr.ID, nil)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("delete missing rule: got %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestGenerateRule(t *testing.T) {
	// No analyst -> 503.
	ts := newTestServer(t, Config{AgentToken: testToken})
	resp := post(t, ts.URL+"/api/rules/generate", "", map[string]string{"description": "detect reverse shells"})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("generate without analyst: got %d, want 503", resp.StatusCode)
	}
	resp.Body.Close()

	// With analyst -> 200 GeneratedRule, and nothing is saved.
	ts2 := newTestServer(t, Config{AgentToken: testToken, Analyst: &fakeAnalyst{}})
	resp = post(t, ts2.URL+"/api/rules/generate", "", map[string]string{"description": "detect reverse shells"})
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("generate: got %d (%s)", resp.StatusCode, b)
	}
	var gr llm.GeneratedRule
	json.NewDecoder(resp.Body).Decode(&gr)
	resp.Body.Close()
	if !gr.Valid {
		t.Fatalf("generated rule: %+v", gr)
	}
	// generate must not persist anything.
	resp = getWith(t, ts2.URL+"/api/rules", "", nil)
	var body struct {
		Rules []store.CustomRule `json:"rules"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if len(body.Rules) != 0 {
		t.Fatalf("generate saved a rule: %+v", body.Rules)
	}
}

func TestIncidentSummary(t *testing.T) {
	// No analyst -> 503.
	ts := newTestServer(t, Config{AgentToken: testToken})
	resp := post(t, ts.URL+"/api/hosts/host-1/incident", "", nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("incident without analyst: got %d, want 503", resp.StatusCode)
	}
	resp.Body.Close()

	ts2 := newTestServer(t, Config{AgentToken: testToken, Analyst: &fakeAnalyst{}})

	// Unknown host -> 404.
	resp = post(t, ts2.URL+"/api/hosts/ghost/incident", "", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("incident unknown host: got %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()

	// Known host with no alerts -> 400.
	hb := post(t, ts2.URL+api.PathHeartbeat, testToken, api.Heartbeat{Host: hostFixture()})
	hb.Body.Close()
	resp = post(t, ts2.URL+"/api/hosts/host-1/incident", "", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("incident no alerts: got %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// With alerts -> 200 IncidentSummary.
	ab := post(t, ts2.URL+api.PathAlerts, testToken,
		api.AlertBatch{Host: hostFixture(), Alerts: []*event.Alert{mkAlert("i1", "critical")}})
	ab.Body.Close()
	resp = post(t, ts2.URL+"/api/hosts/host-1/incident", "", nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("incident: got %d (%s)", resp.StatusCode, b)
	}
	var sum llm.IncidentSummary
	json.NewDecoder(resp.Body).Decode(&sum)
	resp.Body.Close()
	if sum.Title == "" {
		t.Fatalf("incident summary: %+v", sum)
	}
}

// TestCreateRuleRejectsBuiltinCollision checks a custom rule id colliding with a
// built-in is rejected at create time.
func TestCreateRuleRejectsBuiltinCollision(t *testing.T) {
	ts := newTestServer(t, Config{})
	ruleYAML := "- id: SBS-PROC-001\n  title: collide\n  event: process\n  match: {field: process.name, value: x}\n"
	resp := post(t, ts.URL+"/api/rules", "", map[string]string{"yaml": ruleYAML, "source": "manual"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("collision create = %d, want 400", resp.StatusCode)
	}
}
