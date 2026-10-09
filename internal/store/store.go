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

// Command statuses.
const (
	StatusPending = "pending"
	StatusSent    = "sent"
	StatusDone    = "done"
	StatusFailed  = "failed"
)

// Store is a handle to the server database. It is safe for concurrent use.
type Store struct {
	db *sql.DB
}

// Host is a stored endpoint with its first/last-seen timestamps.
type Host struct {
	api.Host
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Alert is a stored alert together with its triage result (raw JSON, if any)
// and the time the server received it.
type Alert struct {
	event.Alert
	Triage    json.RawMessage `json:"triage,omitempty"`
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
	mitre        TEXT NOT NULL DEFAULT '[]',
	event_json   TEXT NOT NULL DEFAULT 'null',
	actions_json TEXT NOT NULL DEFAULT 'null',
	triage_json  TEXT,
	created_at   INTEGER NOT NULL
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
INSERT INTO hosts (id, hostname, os, kernel, arch, agent_version, process_source, first_seen, last_seen, ips)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	hostname=excluded.hostname, os=excluded.os, kernel=excluded.kernel, arch=excluded.arch,
	agent_version=excluded.agent_version, process_source=excluded.process_source,
	last_seen=excluded.last_seen, ips=excluded.ips`,
		h.ID, h.Hostname, h.OS, h.Kernel, h.Arch, h.AgentVersion, h.ProcessSource, now, now, string(ips))
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
	(id, host_id, time, rule_id, title, severity, signature, mitre, event_json, actions_json, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
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
		res, err := stmt.Exec(a.ID, hostID, a.Time.UnixNano(), a.RuleID, a.Title, a.Severity,
			a.Signature, string(mitre), string(ev), string(actions), now)
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

const alertCols = `id, host_id, time, rule_id, title, severity, signature, mitre, event_json, actions_json, triage_json, created_at`

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
		a                  Alert
		hostID             string
		tns, cns           int64
		mitre, ev, actions string
		triage             sql.NullString
	)
	if err := rows.Scan(&a.ID, &hostID, &tns, &a.RuleID, &a.Title, &a.Severity,
		&a.Signature, &mitre, &ev, &actions, &triage, &cns); err != nil {
		return nil, err
	}
	a.Host = hostID
	a.Time = time.Unix(0, tns).UTC()
	a.CreatedAt = time.Unix(0, cns).UTC()
	_ = json.Unmarshal([]byte(mitre), &a.MITRE)
	_ = json.Unmarshal([]byte(ev), &a.Event)
	_ = json.Unmarshal([]byte(actions), &a.Actions)
	if triage.Valid && triage.String != "" {
		a.Triage = json.RawMessage(triage.String)
	}
	return &a, nil
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
SELECT id, hostname, os, kernel, arch, agent_version, process_source, first_seen, last_seen, ips
FROM hosts ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Host
	for rows.Next() {
		var (
			h     Host
			first int64
			last  int64
			ips   string
		)
		if err := rows.Scan(&h.ID, &h.Hostname, &h.OS, &h.Kernel, &h.Arch, &h.AgentVersion,
			&h.ProcessSource, &first, &last, &ips); err != nil {
			return nil, err
		}
		h.FirstSeen = time.Unix(0, first).UTC()
		h.LastSeen = time.Unix(0, last).UTC()
		_ = json.Unmarshal([]byte(ips), &h.IPs)
		out = append(out, &h)
	}
	return out, rows.Err()
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
