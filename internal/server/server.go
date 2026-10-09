// Package server is the sbs-server: it ingests alerts and heartbeats from
// agents, hands back queued response commands, and serves a web console
// (dashboard + JSON API) backed by the store.
//
// Agent endpoints require a bearer token (api: Authorization: Bearer <token>).
// The console endpoints are unauthenticated and are expected to be bound to
// localhost (see cmd/sbs-server).
package server

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/avaadrian/sbs/internal/api"
	"github.com/avaadrian/sbs/internal/event"
	"github.com/avaadrian/sbs/internal/llm"
	"github.com/avaadrian/sbs/internal/store"
)

//go:embed dashboard.html
var dashboardHTML string

const (
	maxBody         = 64 << 20 // decoded request body cap (alert batches)
	refreshInterval = 4 * time.Second
	defaultLimit    = 100
	maxLimit        = 1000
)

// Config configures a Server.
type Config struct {
	// AgentToken authenticates agents. An empty token effectively disables
	// agent authentication (any request passes), so set one in production.
	AgentToken string
	// Analyst performs AI triage. It may be nil, in which case auto-triage is
	// off and the on-demand triage endpoint returns 503.
	Analyst llm.Analyst
	// AutoTriageMinSeverity is the lowest severity that is triaged
	// automatically on ingest (info|low|medium|high|critical). Empty disables
	// auto-triage.
	AutoTriageMinSeverity string
}

// Server serves the agent and console HTTP APIs.
type Server struct {
	st            *store.Store
	cfg           Config
	tmpl          *template.Template
	triageTimeout time.Duration
	minSevRank    int
	wg            sync.WaitGroup
}

// New builds a Server. The returned Server does not start listening; use
// Handler with an http.Server.
func New(st *store.Store, cfg Config) *Server {
	return &Server{
		st:            st,
		cfg:           cfg,
		tmpl:          template.Must(template.New("dashboard").Parse(dashboardHTML)),
		triageTimeout: 45 * time.Second,
		minSevRank:    severityRank(cfg.AutoTriageMinSeverity),
	}
}

// Handler returns the HTTP router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Agent endpoints (bearer-token authenticated).
	mux.HandleFunc("POST "+api.PathAlerts, s.authed(s.handleAlerts))
	mux.HandleFunc("POST "+api.PathHeartbeat, s.authed(s.handleHeartbeat))
	mux.HandleFunc("POST "+api.PathCommandResult, s.authed(s.handleCommandResult))

	// Console: dashboard + JSON API (unauthenticated; bind to localhost).
	mux.HandleFunc("GET /{$}", s.handleDashboard)
	mux.HandleFunc("GET /api/overview", s.handleOverview)
	mux.HandleFunc("GET /api/hosts", s.handleHosts)
	mux.HandleFunc("GET /api/alerts", s.handleListAlerts)
	mux.HandleFunc("GET /api/alerts/{id}", s.handleGetAlert)
	mux.HandleFunc("POST /api/alerts/{id}/triage", s.handleTriage)
	mux.HandleFunc("POST /api/hosts/{id}/commands", s.handleEnqueueCommand)
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
	cmds, err := s.st.PendingCommands(hb.Host.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.HeartbeatResponse{ServerTime: time.Now().UTC(), Commands: cmds})
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

// autoTriage triages one alert in the background. It never blocks the caller
// and recovers from panics in the Analyst.
func (s *Server) autoTriage(a *event.Alert, host string) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
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
	writeJSON(w, http.StatusOK, map[string]any{
		"time":   time.Now().UTC(),
		"hosts":  hosts,
		"counts": counts,
		"alerts": alerts,
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

func (s *Server) fail(w http.ResponseWriter, err error) {
	log.Printf("server: %v", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
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
