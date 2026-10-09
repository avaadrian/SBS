// Package server is the sbs-server: it ingests alerts and heartbeats from
// agents, hands back queued response commands, and serves a web console
// (dashboard + JSON API) backed by the store.
//
// Agent endpoints require the agent bearer token (Authorization: Bearer
// <token>). The console is protected by an operator token (Config.ConsoleToken)
// accepted as either the session cookie set by POST /api/login or an
// Authorization: Bearer header; when no console token is set the console is
// open and must be bound to localhost (see cmd/sbs-server). State-changing
// console requests additionally pass the CSRF guard.
package server

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/avaadrian/sbs/internal/api"
	"github.com/avaadrian/sbs/internal/event"
	"github.com/avaadrian/sbs/internal/llm"
	"github.com/avaadrian/sbs/internal/rules"
	"github.com/avaadrian/sbs/internal/store"
)

//go:embed dashboard.html
var dashboardHTML string

const (
	maxBody         = 64 << 20 // decoded request body cap (alert batches)
	refreshInterval = 4 * time.Second
	defaultLimit    = 100
	maxLimit        = 1000

	sessionCookie = "sbs_session"
	sessionTTL    = 12 * time.Hour
	loginWindow   = time.Minute // per-IP login-failure window
	loginMaxFails = 5           // failures per window before 429
	incidentMax   = 50          // alerts summarized per incident
)

// Config configures a Server.
type Config struct {
	// AgentToken authenticates agents. An empty token effectively disables
	// agent authentication (any request passes), so set one in production.
	AgentToken string
	// ConsoleToken authenticates console operators (cookie or bearer). An empty
	// token leaves the console open (localhost only); a warning is logged.
	ConsoleToken string
	// TLS reports whether the server is served over TLS, so the session cookie
	// is set Secure.
	TLS bool
	// Analyst performs AI triage. It may be nil, in which case auto-triage is
	// off and the on-demand triage endpoint returns 503.
	Analyst llm.Analyst
	// AutoTriageMinSeverity is the lowest severity that is triaged
	// automatically on ingest (info|low|medium|high|critical). Empty disables
	// auto-triage.
	AutoTriageMinSeverity string
}

// Server serves the agent and console HTTP APIs.
// maxConcurrentTriage bounds background auto-triage goroutines (and therefore
// concurrent LLM calls) so a flood of high-severity alerts cannot exhaust
// memory or run up unbounded model cost.
const maxConcurrentTriage = 4

type Server struct {
	st            *store.Store
	cfg           Config
	tmpl          *template.Template
	triageTimeout time.Duration
	minSevRank    int
	wg            sync.WaitGroup
	sem           chan struct{} // bounds concurrent auto-triage goroutines

	sessMu   sync.Mutex
	sessions map[string]time.Time // session id -> expiry

	failMu     sync.Mutex
	loginFails map[string][]time.Time // client IP -> recent failure times
}

// New builds a Server. The returned Server does not start listening; use
// Handler with an http.Server.
func New(st *store.Store, cfg Config) *Server {
	if cfg.ConsoleToken == "" {
		log.Print("warning: no console token set; the console is open — bind it to localhost")
	}
	return &Server{
		st:            st,
		cfg:           cfg,
		tmpl:          template.Must(template.New("dashboard").Parse(dashboardHTML)),
		triageTimeout: 45 * time.Second,
		minSevRank:    severityRank(cfg.AutoTriageMinSeverity),
		sem:           make(chan struct{}, maxConcurrentTriage),
		sessions:      map[string]time.Time{},
		loginFails:    map[string][]time.Time{},
	}
}

// Handler returns the HTTP router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Agent endpoints (agent-bearer-token authenticated).
	mux.HandleFunc("POST "+api.PathAlerts, s.authed(s.handleAlerts))
	mux.HandleFunc("POST "+api.PathHeartbeat, s.authed(s.handleHeartbeat))
	mux.HandleFunc("POST "+api.PathCommandResult, s.authed(s.handleCommandResult))
	mux.HandleFunc("GET "+api.PathRules, s.authed(s.handleAgentRules))

	// Console: dashboard + the unauthenticated auth endpoints. GET / always
	// serves the page; the page calls GET /api/session and logs in as needed.
	mux.HandleFunc("GET /{$}", s.handleDashboard)
	mux.HandleFunc("GET /api/session", s.handleSession)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)

	// Console JSON API (operator-authenticated via cookie or bearer).
	ac := s.authedConsole
	mux.HandleFunc("GET /api/overview", ac(s.handleOverview))
	mux.HandleFunc("GET /api/hosts", ac(s.handleHosts))
	mux.HandleFunc("GET /api/alerts", ac(s.handleListAlerts))
	mux.HandleFunc("GET /api/alerts/{id}", ac(s.handleGetAlert))
	mux.HandleFunc("POST /api/alerts/{id}/triage", ac(s.handleTriage))
	mux.HandleFunc("POST /api/alerts/{id}/approve", ac(s.handleApprove))
	mux.HandleFunc("POST /api/alerts/{id}/decline", ac(s.handleDecline))
	mux.HandleFunc("POST /api/hosts/{id}/commands", ac(s.handleEnqueueCommand))
	mux.HandleFunc("POST /api/hosts/{id}/mode", ac(s.handleSetMode))
	mux.HandleFunc("POST /api/hosts/{id}/incident", ac(s.handleIncident))
	mux.HandleFunc("GET /api/rules", ac(s.handleListRules))
	mux.HandleFunc("POST /api/rules", ac(s.handleCreateRule))
	mux.HandleFunc("POST /api/rules/generate", ac(s.handleGenerateRule))
	mux.HandleFunc("POST /api/rules/{id}/enabled", ac(s.handleSetRuleEnabled))
	mux.HandleFunc("DELETE /api/rules/{id}", ac(s.handleDeleteRule))
	return mux
}

// Wait blocks until all in-flight background triage goroutines finish. It is
// used for graceful shutdown.
func (s *Server) Wait() { s.wg.Wait() }

// --- agent endpoints ---

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	var batch api.AlertBatch
	if err := decodeJSON(r, &batch); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if batch.Host.ID == "" {
		http.Error(w, "missing host id", http.StatusBadRequest)
		return
	}
	if err := s.st.UpsertHost(batch.Host); err != nil {
		s.fail(w, err)
		return
	}
	accepted, duplicate, err := s.st.InsertAlerts(batch.Host.ID, batch.Alerts)
	if err != nil {
		s.fail(w, err)
		return
	}
	if s.cfg.Analyst != nil && s.minSevRank > 0 {
		desc := hostDesc(batch.Host)
		for _, a := range batch.Alerts {
			if a != nil && severityRank(a.Severity) >= s.minSevRank {
				s.autoTriage(a, desc)
			}
		}
	}
	writeJSON(w, http.StatusAccepted, api.AlertBatchResponse{Accepted: accepted, Duplicate: duplicate})
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var hb api.Heartbeat
	if err := decodeJSON(r, &hb); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if hb.Host.ID == "" {
		http.Error(w, "missing host id", http.StatusBadRequest)
		return
	}
	if err := s.st.UpsertHost(hb.Host); err != nil {
		s.fail(w, err)
		return
	}
	// Persist the agent-reported status (what rule set it loaded, any load
	// error, and whether its auto-response breaker tripped).
	if err := s.st.SetHostStatus(hb.Host.ID, hb.RulesVersion, hb.RulesError, hb.AutoResponseTripped); err != nil {
		s.fail(w, err)
		return
	}
	cmds, err := s.st.PendingCommands(hb.Host.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	mode, err := s.st.GetDesiredMode(hb.Host.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	rs, err := s.currentRuleSet()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.HeartbeatResponse{
		ServerTime:   time.Now().UTC(),
		Commands:     cmds,
		ResponseMode: mode,
		RulesVersion: rs.Version,
	})
}

func (s *Server) handleCommandResult(w http.ResponseWriter, r *http.Request) {
	var res api.CommandResult
	if err := decodeJSON(r, &res); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	// A result for an unknown command is treated as already handled.
	if err := s.st.CompleteCommand(res); err != nil && err != store.ErrNotFound {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAgentRules serves the enabled custom rule set to agents (agent-token
// authed) as api.RuleSet: the enabled rules concatenated as one YAML list plus
// the current version.
func (s *Server) handleAgentRules(w http.ResponseWriter, r *http.Request) {
	rs, err := s.currentRuleSet()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rs)
}

// autoTriage triages one alert in the background. It never blocks the caller,
// bounds the number of concurrent triage goroutines (dropping auto-triage when
// saturated — the console can still trigger it on demand), and recovers from
// panics in the Analyst.
func (s *Server) autoTriage(a *event.Alert, host string) {
	select {
	case s.sem <- struct{}{}: // acquire a slot, or skip if at capacity
	default:
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { <-s.sem }()
		defer func() {
			if p := recover(); p != nil {
				log.Printf("server: auto-triage panic for %s: %v", a.ID, p)
			}
		}()
		// Skip if already triaged (e.g. a retried/duplicate upload).
		if existing, err := s.st.GetAlert(a.ID); err == nil && len(existing.Triage) > 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.triageTimeout)
		defer cancel()
		tr, err := s.cfg.Analyst.Triage(ctx, llm.TriageInput{Alert: a, Host: host})
		if err != nil {
			log.Printf("server: auto-triage %s: %v", a.ID, err)
			return
		}
		raw, err := json.Marshal(tr)
		if err != nil {
			return
		}
		if err := s.st.SetTriage(a.ID, raw); err != nil {
			log.Printf("server: store triage %s: %v", a.ID, err)
		}
	}()
}

// --- console endpoints ---

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct {
		AIEnabled bool
		RefreshMs int
	}{
		AIEnabled: s.cfg.Analyst != nil,
		RefreshMs: int(refreshInterval / time.Millisecond),
	}
	if err := s.tmpl.Execute(w, data); err != nil {
		log.Printf("server: dashboard render: %v", err)
	}
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.st.ListHosts()
	if err != nil {
		s.fail(w, err)
		return
	}
	counts, err := s.st.CountsBySeverity(time.Time{})
	if err != nil {
		s.fail(w, err)
		return
	}
	alerts, err := s.st.ListAlerts(store.AlertFilter{Limit: defaultLimit})
	if err != nil {
		s.fail(w, err)
		return
	}
	approvals, err := s.st.ListPendingApprovals(defaultLimit)
	if err != nil {
		s.fail(w, err)
		return
	}
	rs, err := s.currentRuleSet()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"time":          time.Now().UTC(),
		"hosts":         hosts,
		"counts":        counts,
		"alerts":        alerts,
		"approvals":     approvals,
		"rules_version": rs.Version,
		"ai":            s.aiInfo(),
	})
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.st.ListHosts()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AlertFilter{HostID: q.Get("host"), Severity: q.Get("severity"), Limit: defaultLimit}
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			if n > maxLimit {
				n = maxLimit
			}
			f.Limit = n
		}
	}
	if since := q.Get("since"); since != "" {
		if d, err := time.ParseDuration(since); err == nil {
			f.Since = time.Now().Add(-d)
		} else if t, err := time.Parse(time.RFC3339, since); err == nil {
			f.Since = t
		}
	}
	alerts, err := s.st.ListAlerts(f)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, alerts)
}

func (s *Server) handleGetAlert(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.GetAlert(r.PathValue("id"))
	if err == store.ErrNotFound {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleTriage(w http.ResponseWriter, r *http.Request) {
	if !guardConsolePOST(w, r, false) {
		return
	}
	if s.cfg.Analyst == nil {
		http.Error(w, "AI analyst not configured", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	a, err := s.st.GetAlert(id)
	if err == store.ErrNotFound {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	in := llm.TriageInput{
		Alert:   &a.Alert,
		Host:    s.hostDescByID(a.Host),
		Related: s.relatedAlerts(a),
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.triageTimeout)
	defer cancel()
	tr, err := s.cfg.Analyst.Triage(ctx, in)
	if err != nil {
		log.Printf("server: triage %s: %v", id, err)
		http.Error(w, "triage failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	raw, err := json.Marshal(tr)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.st.SetTriage(id, raw); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tr)
}

func (s *Server) handleEnqueueCommand(w http.ResponseWriter, r *http.Request) {
	if !guardConsolePOST(w, r, true) {
		return
	}
	hostID := r.PathValue("id")
	var req struct {
		Type    string `json:"type"`
		PID     int    `json:"pid"`
		Path    string `json:"path"`
		Reason  string `json:"reason"`
		AlertID string `json:"alert_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	switch req.Type {
	case api.CmdKill:
		if req.PID <= 0 {
			http.Error(w, "kill requires pid", http.StatusBadRequest)
			return
		}
	case api.CmdQuarantine, api.CmdScan:
		if req.Path == "" {
			http.Error(w, req.Type+" requires path", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "unknown command type: "+req.Type, http.StatusBadRequest)
		return
	}
	cmd := api.Command{
		ID:      newID(),
		Type:    req.Type,
		PID:     req.PID,
		Path:    req.Path,
		Reason:  req.Reason,
		AlertID: req.AlertID,
		Created: time.Now().UTC(),
	}
	if err := s.st.EnqueueCommand(hostID, cmd); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, cmd)
}

// handleApprove approves an alert's proposed response actions (ask mode): it
// enqueues the corresponding command(s) for the alert's host, derived from the
// alert's own event, and marks the alert approved.
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	if !guardConsolePOST(w, r, false) {
		return
	}
	a, err := s.st.GetAlert(r.PathValue("id"))
	if err == store.ErrNotFound {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if len(a.Proposed) == 0 {
		http.Error(w, "alert has no proposed actions", http.StatusBadRequest)
		return
	}
	cmds := commandsFor(&a.Alert)
	if len(cmds) == 0 {
		http.Error(w, "proposed actions could not be resolved from the alert", http.StatusBadRequest)
		return
	}
	for _, c := range cmds {
		if err := s.st.EnqueueCommand(a.Host, c); err != nil {
			s.fail(w, err)
			return
		}
	}
	if err := s.st.SetApproval(a.ID, store.ApprovalApproved); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approved": true, "commands": cmds})
}

// handleDecline dismisses an alert's proposed actions without acting.
func (s *Server) handleDecline(w http.ResponseWriter, r *http.Request) {
	if !guardConsolePOST(w, r, false) {
		return
	}
	if err := s.st.SetApproval(r.PathValue("id"), store.ApprovalDismissed); err == store.ErrNotFound {
		http.Error(w, "not found", http.StatusNotFound)
		return
	} else if err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSetMode sets (or, with an empty mode, clears) a host's operator
// response-mode override, delivered to the agent in its next heartbeat.
func (s *Server) handleSetMode(w http.ResponseWriter, r *http.Request) {
	if !guardConsolePOST(w, r, true) {
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	switch req.Mode {
	case "", "off", "ask", "auto":
	default:
		http.Error(w, "mode must be one of off, ask, auto, or empty", http.StatusBadRequest)
		return
	}
	if err := s.st.SetDesiredMode(r.PathValue("id"), req.Mode); err == store.ErrNotFound {
		http.Error(w, "unknown host", http.StatusNotFound)
		return
	} else if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"desired_mode": req.Mode})
}

// handleListRules returns the stored custom rules (newest first) and the
// current enabled-rule-set version.
func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListCustomRules()
	if err != nil {
		s.fail(w, err)
		return
	}
	rs, err := s.currentRuleSet()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": rs.Version, "rules": list})
}

// handleCreateRule validates and stores one custom rule. The body YAML must be
// exactly one valid rule whose id does not collide with another custom rule.
func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	if !guardConsolePOST(w, r, true) {
		return
	}
	var req struct {
		YAML   string `json:"yaml"`
		Source string `json:"source"`
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	parsed, err := rules.Parse([]byte(req.YAML), "custom rule")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(parsed) != 1 {
		http.Error(w, "body must contain exactly one rule", http.StatusBadRequest)
		return
	}
	rule := parsed[0]
	source := req.Source
	if source != "ai" {
		source = "manual"
	}
	cr := store.CustomRule{
		ID:        "cr_" + newID(),
		RuleID:    rule.ID,
		Title:     rule.Title,
		Severity:  rule.Severity,
		Event:     rule.Event,
		YAML:      strings.TrimSpace(req.YAML),
		Enabled:   true,
		Source:    source,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.st.AddCustomRule(cr); err == store.ErrDuplicate {
		http.Error(w, "a custom rule with id "+rule.ID+" already exists", http.StatusBadRequest)
		return
	} else if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, cr)
}

// handleSetRuleEnabled enables or disables a stored custom rule.
func (s *Server) handleSetRuleEnabled(w http.ResponseWriter, r *http.Request) {
	if !guardConsolePOST(w, r, true) {
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	cr, err := s.st.SetCustomRuleEnabled(r.PathValue("id"), req.Enabled)
	if err == store.ErrNotFound {
		http.Error(w, "not found", http.StatusNotFound)
		return
	} else if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cr)
}

// handleDeleteRule removes a stored custom rule.
func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	if !guardConsolePOST(w, r, false) {
		return
	}
	if err := s.st.DeleteCustomRule(r.PathValue("id")); err == store.ErrNotFound {
		http.Error(w, "not found", http.StatusNotFound)
		return
	} else if err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGenerateRule asks the AI analyst for a detection rule from a natural
// language description. It returns the generated (validated) rule without
// saving it; the operator reviews and posts it to /api/rules to store it.
func (s *Server) handleGenerateRule(w http.ResponseWriter, r *http.Request) {
	if !guardConsolePOST(w, r, true) {
		return
	}
	if s.cfg.Analyst == nil {
		http.Error(w, "AI analyst not configured", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Description string `json:"description"`
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Description) == "" {
		http.Error(w, "description is required", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.triageTimeout)
	defer cancel()
	gr, err := s.cfg.Analyst.GenerateRule(ctx, req.Description)
	if err != nil {
		log.Printf("server: generate rule: %v", err)
		http.Error(w, "rule generation failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, gr)
}

// handleIncident summarizes a host's most recent alerts with the AI analyst.
func (s *Server) handleIncident(w http.ResponseWriter, r *http.Request) {
	if !guardConsolePOST(w, r, false) {
		return
	}
	if s.cfg.Analyst == nil {
		http.Error(w, "AI analyst not configured", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	if !s.hostExists(id) {
		http.Error(w, "unknown host", http.StatusNotFound)
		return
	}
	stored, err := s.st.ListAlerts(store.AlertFilter{HostID: id, Limit: incidentMax})
	if err != nil {
		s.fail(w, err)
		return
	}
	if len(stored) == 0 {
		http.Error(w, "host has no alerts", http.StatusBadRequest)
		return
	}
	alerts := make([]*event.Alert, 0, len(stored))
	for _, a := range stored {
		cp := a.Alert
		alerts = append(alerts, &cp)
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.triageTimeout)
	defer cancel()
	sum, err := s.cfg.Analyst.SummarizeIncident(ctx, s.hostDescByID(id), alerts)
	if err != nil {
		log.Printf("server: incident %s: %v", id, err)
		http.Error(w, "incident summary failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

// --- console auth ---

// handleSession reports whether auth is required, whether this request is
// already authenticated, and the AI analyst state. It needs no auth: the
// dashboard calls it to decide whether to show a login form.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"auth_required": s.cfg.ConsoleToken != "",
		"authenticated": s.isAuthed(r),
		"ai":            s.aiInfo(),
	})
}

// handleLogin exchanges the console token for a session cookie. It is
// rate-limited per client IP (5 failures/min -> 429) and compares the token in
// constant time.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !guardConsolePOST(w, r, true) {
		return
	}
	ip := clientIP(r)
	if s.loginBlocked(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many login attempts; try again later"})
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	// An open console (no token) accepts any login; otherwise compare in
	// constant time.
	ok := s.cfg.ConsoleToken == "" ||
		subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.cfg.ConsoleToken)) == 1
	if !ok {
		s.noteLoginFailure(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}
	sid := newSessionID()
	s.sessMu.Lock()
	s.sessions[sid] = time.Now().Add(sessionTTL)
	s.sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLS,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(sessionTTL),
		MaxAge:   int(sessionTTL / time.Second),
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleLogout clears the session and its cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !guardConsolePOST(w, r, false) {
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		s.sessMu.Lock()
		delete(s.sessions, c.Value)
		s.sessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLS,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

// commandsFor builds the response commands for an alert's proposed actions,
// deriving pid/path from the alert's event (the same plan the agent proposed).
func commandsFor(a *event.Alert) []api.Command {
	now := time.Now().UTC()
	reason := "approved: " + a.RuleID
	var cmds []api.Command
	for _, kind := range a.Proposed {
		c := api.Command{ID: newID(), Type: kind, Reason: reason, AlertID: a.ID, Created: now}
		switch kind {
		case api.CmdKill:
			if a.Event == nil || a.Event.Process == nil || a.Event.Process.PID <= 0 {
				continue
			}
			c.PID = a.Event.Process.PID
		case api.CmdQuarantine:
			switch {
			case a.Signature != "" && a.Event != nil && a.Event.Process != nil && a.Event.Process.Exe != "":
				c.Path = strings.TrimSuffix(a.Event.Process.Exe, " (deleted)")
			case a.Event != nil && a.Event.File != nil && a.Event.File.Path != "":
				c.Path = a.Event.File.Path
			default:
				continue
			}
		default:
			continue
		}
		cmds = append(cmds, c)
	}
	return cmds
}

// relatedAlerts returns recent alerts on the same host, excluding a itself.
func (s *Server) relatedAlerts(a *store.Alert) []*event.Alert {
	rows, err := s.st.ListAlerts(store.AlertFilter{HostID: a.Host, Limit: 25})
	if err != nil {
		return nil
	}
	var out []*event.Alert
	for _, row := range rows {
		if row.ID == a.ID {
			continue
		}
		cp := row.Alert
		out = append(out, &cp)
	}
	return out
}

func (s *Server) hostDescByID(id string) string {
	if hosts, err := s.st.ListHosts(); err == nil {
		for _, h := range hosts {
			if h.ID == id {
				return hostDesc(h.Host)
			}
		}
	}
	return id
}

// --- helpers ---

func (s *Server) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.cfg.AgentToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// authedConsole gates the console JSON API: a request must carry a valid
// session cookie or the console bearer token. When no console token is
// configured the console is open and every request passes.
func (s *Server) authedConsole(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.isAuthed(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		h(w, r)
	}
}

// isAuthed reports whether r is authenticated for the console: open console,
// matching bearer token, or a live session cookie.
func (s *Server) isAuthed(r *http.Request) bool {
	if s.cfg.ConsoleToken == "" {
		return true
	}
	if subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.cfg.ConsoleToken)) == 1 {
		return true
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		return s.validSession(c.Value)
	}
	return false
}

// validSession reports whether id is a live (unexpired) session, pruning it if
// it has expired.
func (s *Server) validSession(id string) bool {
	if id == "" {
		return false
	}
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	exp, ok := s.sessions[id]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.sessions, id)
		return false
	}
	return true
}

// loginBlocked reports whether ip has hit the login failure rate limit,
// pruning failures older than the window.
func (s *Server) loginBlocked(ip string) bool {
	s.failMu.Lock()
	defer s.failMu.Unlock()
	return len(s.pruneFailsLocked(ip)) >= loginMaxFails
}

// noteLoginFailure records a failed login for ip.
func (s *Server) noteLoginFailure(ip string) {
	s.failMu.Lock()
	defer s.failMu.Unlock()
	s.loginFails[ip] = append(s.pruneFailsLocked(ip), time.Now())
}

// pruneFailsLocked drops ip's failures older than loginWindow and returns the
// ones kept. The caller must hold failMu.
func (s *Server) pruneFailsLocked(ip string) []time.Time {
	cutoff := time.Now().Add(-loginWindow)
	kept := s.loginFails[ip][:0]
	for _, t := range s.loginFails[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(s.loginFails, ip)
	} else {
		s.loginFails[ip] = kept
	}
	return kept
}

// aiInfo describes the AI analyst state for the session/overview payloads.
func (s *Server) aiInfo() map[string]any {
	provider := ""
	if s.cfg.Analyst != nil {
		provider = s.cfg.Analyst.Name()
	}
	return map[string]any{"enabled": s.cfg.Analyst != nil, "provider": provider}
}

// currentRuleSet returns the enabled custom rules as one YAML list plus a
// version that is a short, stable sha256 of that YAML.
func (s *Server) currentRuleSet() (api.RuleSet, error) {
	y, err := s.st.EnabledRuleYAML()
	if err != nil {
		return api.RuleSet{}, err
	}
	return api.RuleSet{Version: rulesVersion(y), YAML: y}, nil
}

// hostExists reports whether a host id is known.
func (s *Server) hostExists(id string) bool {
	hosts, err := s.st.ListHosts()
	if err != nil {
		return false
	}
	for _, h := range hosts {
		if h.ID == id {
			return true
		}
	}
	return false
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	log.Printf("server: %v", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// crossSite reports whether a state-changing console request looks like a
// cross-site browser request (CSRF). Browsers send Sec-Fetch-Site on fetch/form
// submissions; anything but same-origin/same-site/none is rejected. Non-browser
// clients (curl) send no such header and are allowed. This complements binding
// the console to localhost, which alone does not stop a visited page from
// POSTing to 127.0.0.1.
func crossSite(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "same-site", "none":
		return false
	default:
		return true
	}
}

// guardConsolePOST rejects cross-site requests and, when a body is expected,
// requires a JSON content type (blocking CSRF "simple requests" that use
// text/plain). It returns false and writes the error if the request is refused.
func guardConsolePOST(w http.ResponseWriter, r *http.Request, requireJSON bool) bool {
	if crossSite(r) {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return false
	}
	if requireJSON {
		ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
		if !strings.EqualFold(strings.TrimSpace(ct), "application/json") {
			http.Error(w, "expected Content-Type: application/json", http.StatusUnsupportedMediaType)
			return false
		}
	}
	return true
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) >= len(p) && strings.EqualFold(h[:len(p)], p) {
		return h[len(p):]
	}
	return ""
}

func decodeJSON(r *http.Request, v any) error {
	var reader io.Reader = r.Body
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			return err
		}
		defer gz.Close()
		reader = gz
	}
	return json.NewDecoder(io.LimitReader(reader, maxBody)).Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("server: encode response: %v", err)
	}
}

func hostDesc(h api.Host) string {
	switch {
	case h.Hostname != "" && h.OS != "":
		return h.Hostname + " (" + h.OS + ")"
	case h.Hostname != "":
		return h.Hostname
	case h.OS != "":
		return h.OS
	default:
		return h.ID
	}
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "info":
		return 1
	case "low":
		return 2
	case "medium":
		return 3
	case "high":
		return 4
	case "critical":
		return 5
	}
	return 0
}

func newID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// newSessionID returns a random 32-byte session id as hex.
func newSessionID() string {
	var b [32]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// rulesVersion is a short, content-stable sha256 of the rule-set YAML. It is
// non-empty even for an empty rule set (so a version always identifies the
// current set).
func rulesVersion(yaml string) string {
	sum := sha256.Sum256([]byte(yaml))
	return hex.EncodeToString(sum[:])[:12]
}

// clientIP is the request's remote address without the port, used to key the
// login rate limiter.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
