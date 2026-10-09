// Package store is the sbs-server persistence layer: hosts, alerts, their
// triage results, and the per-host command queue, kept in a single SQLite
// database via the pure-Go modernc.org/sqlite driver (no cgo).
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/avaadrian/sbs/internal/api"
	"github.com/avaadrian/sbs/internal/event"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrDuplicate is returned when a custom rule's rule_id collides with one
// already stored.
var ErrDuplicate = errors.New("store: duplicate rule id")

// Command statuses.
const (
	StatusPending = "pending"
	StatusSent    = "sent"
	StatusDone    = "done"
	StatusFailed  = "failed"
)

// Approval statuses for an alert's proposed response actions (ask mode).
const (
	ApprovalPending   = "pending"
	ApprovalApproved  = "approved"
	ApprovalDismissed = "dismissed"
)

// Store is a handle to the server database. It is safe for concurrent use.
type Store struct {
	db *sql.DB
}

// Host is a stored endpoint with its first/last-seen timestamps.
//
// DesiredMode is the operator override pushed to the agent ("" when none);
// RulesVersion, RulesError and AutoResponseTripped are the agent's own status
// as of its last heartbeat (what rule set it has loaded, whether it failed to
// load, and whether its auto-response circuit breaker has tripped).
type Host struct {
	api.Host
	DesiredMode         string    `json:"desired_mode"`
	RulesVersion        string    `json:"rules_version"`
	RulesError          string    `json:"rules_error"`
	AutoResponseTripped bool      `json:"auto_response_tripped"`
	FirstSeen           time.Time `json:"first_seen"`
	LastSeen            time.Time `json:"last_seen"`
}

// CustomRule is one operator- or AI-authored detection rule stored by the
// server and distributed to agents. YAML is the single-rule YAML as posted;
// RuleID/Title/Severity/Event are extracted from it for display.
type CustomRule struct {
	ID        string    `json:"id"`
	RuleID    string    `json:"rule_id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Event     string    `json:"event"`
	YAML      string    `json:"yaml"`
	Enabled   bool      `json:"enabled"`
	Source    string    `json:"source"` // manual | ai
	CreatedAt time.Time `json:"created_at"`
}

// Alert is a stored alert together with its triage result (raw JSON, if any)
// and the time the server received it.
type Alert struct {
	event.Alert
	Triage    json.RawMessage `json:"triage,omitempty"`
	Approval  string          `json:"approval,omitempty"` // "", pending, approved, dismissed
	CreatedAt time.Time       `json:"created_at"`
}

// AlertFilter selects and bounds a ListAlerts query. The zero value selects
// every alert, newest first.
type AlertFilter struct {
	HostID   string
	Severity string
	Since    time.Time
	Limit    int
}

const schema = `
CREATE TABLE IF NOT EXISTS hosts (
	id             TEXT PRIMARY KEY,
	hostname       TEXT NOT NULL DEFAULT '',
	os             TEXT NOT NULL DEFAULT '',
	kernel         TEXT NOT NULL DEFAULT '',
	arch           TEXT NOT NULL DEFAULT '',
	agent_version  TEXT NOT NULL DEFAULT '',
	process_source TEXT NOT NULL DEFAULT '',
	response_mode  TEXT NOT NULL DEFAULT '',
	desired_mode   TEXT NOT NULL DEFAULT '',
	rules_version  TEXT NOT NULL DEFAULT '',
	rules_error    TEXT NOT NULL DEFAULT '',
	auto_tripped   INTEGER NOT NULL DEFAULT 0,
	first_seen     INTEGER NOT NULL,
	last_seen      INTEGER NOT NULL,
	ips            TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS alerts (
	id           TEXT PRIMARY KEY,
	host_id      TEXT NOT NULL,
	time         INTEGER NOT NULL,
	rule_id      TEXT NOT NULL DEFAULT '',
	title        TEXT NOT NULL DEFAULT '',
	severity     TEXT NOT NULL DEFAULT '',
	signature    TEXT NOT NULL DEFAULT '',
	mitre         TEXT NOT NULL DEFAULT '[]',
	event_json    TEXT NOT NULL DEFAULT 'null',
	actions_json  TEXT NOT NULL DEFAULT 'null',
	proposed_json TEXT NOT NULL DEFAULT '[]',
	approval      TEXT NOT NULL DEFAULT '',
	triage_json   TEXT,
	created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(host_id);
CREATE INDEX IF NOT EXISTS idx_alerts_sev  ON alerts(severity);
CREATE TABLE IF NOT EXISTS commands (
	id       TEXT PRIMARY KEY,
	host_id  TEXT NOT NULL,
	type     TEXT NOT NULL,
	pid      INTEGER NOT NULL DEFAULT 0,
	path     TEXT NOT NULL DEFAULT '',
	reason   TEXT NOT NULL DEFAULT '',
	alert_id TEXT NOT NULL DEFAULT '',
	status   TEXT NOT NULL DEFAULT 'pending',
	output   TEXT NOT NULL DEFAULT '',
	created  INTEGER NOT NULL,
	updated  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_commands_host ON commands(host_id, status);
CREATE TABLE IF NOT EXISTS custom_rules (
	id       TEXT PRIMARY KEY,
	rule_id  TEXT NOT NULL UNIQUE,
	title    TEXT NOT NULL DEFAULT '',
	severity TEXT NOT NULL DEFAULT '',
	event    TEXT NOT NULL DEFAULT '',
	yaml     TEXT NOT NULL DEFAULT '',
	enabled  INTEGER NOT NULL DEFAULT 1,
	source   TEXT NOT NULL DEFAULT '',
	created  INTEGER NOT NULL
);
`

// Open opens (creating if needed) the database at path. An empty path or
// ":memory:" uses a shared in-memory database that lives for the lifetime of
// the returned Store.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)"
	if path == "" || path == ":memory:" {
		dsn = ":memory:"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// A single connection serializes access (SQLite serializes writes anyway)
	// and keeps a private in-memory database alive for the Store's lifetime
	// (each Store gets its own, rather than a process-wide shared cache).
	db.SetMaxOpenConns(1)
	db.SetConnMaxIdleTime(0)
	db.SetConnMaxLifetime(0)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: init schema: %w", err)
	}
	// Best-effort migrations for databases created before these columns existed.
	// A "duplicate column" error just means the column is already present.
	for _, mig := range []string{
		`ALTER TABLE alerts ADD COLUMN proposed_json TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE alerts ADD COLUMN approval TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE hosts ADD COLUMN response_mode TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE hosts ADD COLUMN desired_mode TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE hosts ADD COLUMN rules_version TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE hosts ADD COLUMN rules_error TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE hosts ADD COLUMN auto_tripped INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := db.Exec(mig); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			db.Close()
			return nil, fmt.Errorf("store: migrate: %w", err)
		}
	}
	return &Store{db: db}, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// UpsertHost inserts or updates a host, always refreshing last_seen and
// preserving the original first_seen.
func (s *Store) UpsertHost(h api.Host) error {
	now := time.Now().UTC().UnixNano()
	ips, _ := json.Marshal(h.IPs)
	_, err := s.db.Exec(`
INSERT INTO hosts (id, hostname, os, kernel, arch, agent_version, process_source, response_mode, first_seen, last_seen, ips)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	hostname=excluded.hostname, os=excluded.os, kernel=excluded.kernel, arch=excluded.arch,
	agent_version=excluded.agent_version, process_source=excluded.process_source,
	response_mode=excluded.response_mode, last_seen=excluded.last_seen, ips=excluded.ips`,
		h.ID, h.Hostname, h.OS, h.Kernel, h.Arch, h.AgentVersion, h.ProcessSource, h.ResponseMode, now, now, string(ips))
	return err
}

// InsertAlerts stores a batch for one host. IDs already present are ignored
// (idempotent upload), so accepted+duplicate == len(alerts).
func (s *Store) InsertAlerts(hostID string, alerts []*event.Alert) (accepted, duplicate int, err error) {
	if len(alerts) == 0 {
		return 0, 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`
INSERT OR IGNORE INTO alerts
	(id, host_id, time, rule_id, title, severity, signature, mitre, event_json, actions_json, proposed_json, approval, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, 0, err
	}
	defer stmt.Close()
	now := time.Now().UTC().UnixNano()
	for _, a := range alerts {
		if a == nil {
			continue
		}
		mitre, _ := json.Marshal(a.MITRE)
		ev, _ := json.Marshal(a.Event)
		actions, _ := json.Marshal(a.Actions)
		proposed, _ := json.Marshal(a.Proposed)
		// An alert the agent is holding for approval starts life pending.
		approval := ""
		if len(a.Proposed) > 0 {
			approval = ApprovalPending
		}
		res, err := stmt.Exec(a.ID, hostID, a.Time.UnixNano(), a.RuleID, a.Title, a.Severity,
			a.Signature, string(mitre), string(ev), string(actions), string(proposed), approval, now)
		if err != nil {
			return accepted, duplicate, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			accepted++
		} else {
			duplicate++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return accepted, duplicate, nil
}

const alertCols = `id, host_id, time, rule_id, title, severity, signature, mitre, event_json, actions_json, proposed_json, approval, triage_json, created_at`

// ListAlerts returns alerts matching the filter, newest first.
func (s *Store) ListAlerts(f AlertFilter) ([]*Alert, error) {
	var where []string
	var args []any
	if f.HostID != "" {
		where = append(where, "host_id = ?")
		args = append(args, f.HostID)
	}
	if f.Severity != "" {
		where = append(where, "severity = ?")
		args = append(args, f.Severity)
	}
	if !f.Since.IsZero() {
		where = append(where, "time >= ?")
		args = append(args, f.Since.UnixNano())
	}
	q := "SELECT " + alertCols + " FROM alerts"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY time DESC, rowid DESC"
	if f.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, f.Limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetAlert returns a single alert by ID, or ErrNotFound.
func (s *Store) GetAlert(id string) (*Alert, error) {
	rows, err := s.db.Query("SELECT "+alertCols+" FROM alerts WHERE id = ?", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, ErrNotFound
	}
	return scanAlert(rows)
}

func scanAlert(rows *sql.Rows) (*Alert, error) {
	var (
		a                            Alert
		hostID                       string
		tns, cns                     int64
		mitre, ev, actions, proposed string
		triage                       sql.NullString
	)
	if err := rows.Scan(&a.ID, &hostID, &tns, &a.RuleID, &a.Title, &a.Severity,
		&a.Signature, &mitre, &ev, &actions, &proposed, &a.Approval, &triage, &cns); err != nil {
		return nil, err
	}
	a.Host = hostID
	a.Time = time.Unix(0, tns).UTC()
	a.CreatedAt = time.Unix(0, cns).UTC()
	_ = json.Unmarshal([]byte(mitre), &a.MITRE)
	_ = json.Unmarshal([]byte(ev), &a.Event)
	_ = json.Unmarshal([]byte(actions), &a.Actions)
	_ = json.Unmarshal([]byte(proposed), &a.Proposed)
	if triage.Valid && triage.String != "" {
		a.Triage = json.RawMessage(triage.String)
	}
	return &a, nil
}

// SetApproval sets an alert's approval status (ask-mode proposals).
func (s *Store) SetApproval(alertID, status string) error {
	res, err := s.db.Exec("UPDATE alerts SET approval = ? WHERE id = ?", status, alertID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListPendingApprovals returns alerts awaiting operator approval, newest first.
func (s *Store) ListPendingApprovals(limit int) ([]*Alert, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT `+alertCols+` FROM alerts WHERE approval = ? ORDER BY time DESC LIMIT ?`,
		ApprovalPending, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetTriage stores (or replaces) the triage JSON for an alert.
func (s *Store) SetTriage(alertID string, triageJSON []byte) error {
	res, err := s.db.Exec("UPDATE alerts SET triage_json = ? WHERE id = ?", string(triageJSON), alertID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListHosts returns every known host, most recently seen first.
func (s *Store) ListHosts() ([]*Host, error) {
	rows, err := s.db.Query(`
SELECT id, hostname, os, kernel, arch, agent_version, process_source, response_mode,
       desired_mode, rules_version, rules_error, auto_tripped, first_seen, last_seen, ips
FROM hosts ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Host
	for rows.Next() {
		var (
			h       Host
			first   int64
			last    int64
			tripped int64
			ips     string
		)
		if err := rows.Scan(&h.ID, &h.Hostname, &h.OS, &h.Kernel, &h.Arch, &h.AgentVersion,
			&h.ProcessSource, &h.ResponseMode, &h.DesiredMode, &h.RulesVersion, &h.RulesError,
			&tripped, &first, &last, &ips); err != nil {
			return nil, err
		}
		h.AutoResponseTripped = tripped != 0
		h.FirstSeen = time.Unix(0, first).UTC()
		h.LastSeen = time.Unix(0, last).UTC()
		_ = json.Unmarshal([]byte(ips), &h.IPs)
		out = append(out, &h)
	}
	return out, rows.Err()
}

// SetDesiredMode sets a host's operator-chosen response mode override. An empty
// mode clears the override. The host must already be known (ErrNotFound
// otherwise).
func (s *Store) SetDesiredMode(hostID, mode string) error {
	res, err := s.db.Exec("UPDATE hosts SET desired_mode = ? WHERE id = ?", mode, hostID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetDesiredMode returns a host's operator override ("" when none or the host
// is unknown).
func (s *Store) GetDesiredMode(hostID string) (string, error) {
	var mode string
	err := s.db.QueryRow("SELECT desired_mode FROM hosts WHERE id = ?", hostID).Scan(&mode)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return mode, err
}

// SetHostStatus records the agent-reported fields from a heartbeat (the rule
// set version it has loaded, any load error, and whether its auto-response
// circuit breaker has tripped). The host must already be known.
func (s *Store) SetHostStatus(hostID, rulesVersion, rulesError string, autoTripped bool) error {
	tripped := 0
	if autoTripped {
		tripped = 1
	}
	res, err := s.db.Exec("UPDATE hosts SET rules_version = ?, rules_error = ?, auto_tripped = ? WHERE id = ?",
		rulesVersion, rulesError, tripped, hostID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountsBySeverity returns alert counts grouped by severity. A zero since
// counts all alerts; otherwise only alerts at or after since.
func (s *Store) CountsBySeverity(since time.Time) (map[string]int, error) {
	q := "SELECT severity, COUNT(*) FROM alerts"
	var args []any
	if !since.IsZero() {
		q += " WHERE time >= ?"
		args = append(args, since.UnixNano())
	}
	q += " GROUP BY severity"
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, err
		}
		out[sev] = n
	}
	return out, rows.Err()
}

// EnqueueCommand adds a command to a host's queue with status "pending".
//
// NOTE: api.Command carries no host field, but the commands table and
// PendingCommands are per-host, so the host ID is passed explicitly. See the
// package/handoff notes.
func (s *Store) EnqueueCommand(hostID string, c api.Command) error {
	created := c.Created
	if created.IsZero() {
		created = time.Now().UTC()
	}
	now := time.Now().UTC().UnixNano()
	_, err := s.db.Exec(`
INSERT INTO commands (id, host_id, type, pid, path, reason, alert_id, status, output, created, updated)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?)`,
		c.ID, hostID, c.Type, c.PID, c.Path, c.Reason, c.AlertID, StatusPending, created.UnixNano(), now)
	return err
}

// commandRetry is how long a "sent" command may go unacknowledged before it is
// re-delivered. A heartbeat response can be lost in transit after the server
// has already marked the command sent; without redelivery the containment
// action would be silently stranded, so stale "sent" commands are re-armed.
// It is a var only so tests can shorten it.
var commandRetry = 2 * time.Minute

// PendingCommands returns a host's deliverable commands (oldest first) — those
// still pending plus any "sent" command unacknowledged for longer than
// commandRetry — and marks them "sent" with a fresh timestamp in the same
// transaction.
func (s *Store) PendingCommands(hostID string) ([]api.Command, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	cutoff := time.Now().Add(-commandRetry).UnixNano()
	rows, err := tx.Query(`
SELECT id, type, pid, path, reason, alert_id, created
FROM commands WHERE host_id = ? AND (status = ? OR (status = ? AND updated < ?))
ORDER BY created ASC, rowid ASC`, hostID, StatusPending, StatusSent, cutoff)
	if err != nil {
		return nil, err
	}
	var cmds []api.Command
	for rows.Next() {
		var c api.Command
		var created int64
		if err := rows.Scan(&c.ID, &c.Type, &c.PID, &c.Path, &c.Reason, &c.AlertID, &created); err != nil {
			rows.Close()
			return nil, err
		}
		c.Created = time.Unix(0, created).UTC()
		cmds = append(cmds, c)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(cmds) == 0 {
		return nil, tx.Commit()
	}
	now := time.Now().UTC().UnixNano()
	for _, c := range cmds {
		if _, err := tx.Exec("UPDATE commands SET status = ?, updated = ? WHERE id = ?", StatusSent, now, c.ID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return cmds, nil
}

const customRuleCols = `id, rule_id, title, severity, event, yaml, enabled, source, created`

// AddCustomRule stores a new custom rule. It returns ErrDuplicate if the
// rule_id already belongs to another stored custom rule.
func (s *Store) AddCustomRule(cr CustomRule) error {
	created := cr.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	enabled := 0
	if cr.Enabled {
		enabled = 1
	}
	_, err := s.db.Exec(`
INSERT INTO custom_rules (`+customRuleCols+`)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cr.ID, cr.RuleID, cr.Title, cr.Severity, cr.Event, cr.YAML, enabled, cr.Source, created.UnixNano())
	if err != nil {
		// UNIQUE(rule_id) violation -> duplicate.
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "constraint") {
			return ErrDuplicate
		}
		return fmt.Errorf("store: add custom rule: %w", err)
	}
	return nil
}

// ListCustomRules returns every stored custom rule, newest first.
func (s *Store) ListCustomRules() ([]*CustomRule, error) {
	rows, err := s.db.Query("SELECT " + customRuleCols + " FROM custom_rules ORDER BY created DESC, rowid DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*CustomRule{}
	for rows.Next() {
		cr, err := scanCustomRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cr)
	}
	return out, rows.Err()
}

// GetCustomRule returns one custom rule by its id, or ErrNotFound.
func (s *Store) GetCustomRule(id string) (*CustomRule, error) {
	rows, err := s.db.Query("SELECT "+customRuleCols+" FROM custom_rules WHERE id = ?", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, ErrNotFound
	}
	return scanCustomRule(rows)
}

// SetCustomRuleEnabled flips a rule's enabled flag and returns the updated rule.
func (s *Store) SetCustomRuleEnabled(id string, enabled bool) (*CustomRule, error) {
	e := 0
	if enabled {
		e = 1
	}
	res, err := s.db.Exec("UPDATE custom_rules SET enabled = ? WHERE id = ?", e, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}
	return s.GetCustomRule(id)
}

// DeleteCustomRule removes a rule by id, or returns ErrNotFound.
func (s *Store) DeleteCustomRule(id string) error {
	res, err := s.db.Exec("DELETE FROM custom_rules WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// EnabledRuleYAML returns the enabled custom rules' YAML concatenated as one
// YAML list, ordered by rule_id so the result is stable for the same content.
func (s *Store) EnabledRuleYAML() (string, error) {
	rows, err := s.db.Query("SELECT yaml FROM custom_rules WHERE enabled = 1 ORDER BY rule_id ASC")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var parts []string
	for rows.Next() {
		var y string
		if err := rows.Scan(&y); err != nil {
			return "", err
		}
		parts = append(parts, strings.TrimRight(y, "\n"))
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return strings.Join(parts, "\n"), nil
}

func scanCustomRule(rows *sql.Rows) (*CustomRule, error) {
	var (
		cr      CustomRule
		enabled int64
		created int64
	)
	if err := rows.Scan(&cr.ID, &cr.RuleID, &cr.Title, &cr.Severity, &cr.Event,
		&cr.YAML, &enabled, &cr.Source, &created); err != nil {
		return nil, err
	}
	cr.Enabled = enabled != 0
	cr.CreatedAt = time.Unix(0, created).UTC()
	return &cr, nil
}

// CompleteCommand records a command's outcome, setting status to "done" or
// "failed" and storing its output.
func (s *Store) CompleteCommand(r api.CommandResult) error {
	status := StatusDone
	if !r.OK {
		status = StatusFailed
	}
	out := r.Output
	if r.Error != "" {
		if out != "" {
			out += "\n"
		}
		out += "error: " + r.Error
	}
	now := time.Now().UTC().UnixNano()
	res, err := s.db.Exec("UPDATE commands SET status = ?, output = ?, updated = ? WHERE id = ?",
		status, out, now, r.CommandID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
