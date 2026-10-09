// Package api defines the wire format between sbs-agent and sbs-server.
//
// Agents authenticate with "Authorization: Bearer <agent token>". All bodies
// are JSON and may be gzip-compressed (Content-Encoding: gzip).
//
//	POST PathAlerts          AlertBatch        -> 202, AlertBatchResponse
//	POST PathHeartbeat       Heartbeat         -> 200, HeartbeatResponse (pending commands)
//	POST PathCommandResult   CommandResult     -> 204
package api

import (
	"time"

	"github.com/avaadrian/sbs/internal/event"
)

// Agent-facing endpoints.
const (
	PathAlerts        = "/api/v1/agent/alerts"
	PathHeartbeat     = "/api/v1/agent/heartbeat"
	PathCommandResult = "/api/v1/agent/commands/result"
)

// Host identifies an endpoint. ID is stable across restarts (derived from
// /etc/machine-id, or a random ID persisted in the agent's state directory).
type Host struct {
	ID            string   `json:"id"`
	Hostname      string   `json:"hostname"`
	OS            string   `json:"os"` // PRETTY_NAME from /etc/os-release
	Kernel        string   `json:"kernel"`
	Arch          string   `json:"arch"`
	IPs           []string `json:"ips,omitempty"`
	AgentVersion  string   `json:"agent_version"`
	ProcessSource string   `json:"process_source"` // netlink | procfs
	ResponseMode  string   `json:"response_mode"`  // off | ask | auto
}

// AlertBatch uploads alerts. Alert IDs make uploads idempotent: the server
// ignores IDs it already stored, so agents may safely retry.
type AlertBatch struct {
	Host   Host           `json:"host"`
	Alerts []*event.Alert `json:"alerts"`
}

// AlertBatchResponse acknowledges a batch.
type AlertBatchResponse struct {
	Accepted  int `json:"accepted"`
	Duplicate int `json:"duplicate"`
}

// Heartbeat is sent periodically; the response carries pending commands.
type Heartbeat struct {
	Host            Host      `json:"host"`
	Time            time.Time `json:"time"`
	UptimeSeconds   float64   `json:"uptime_s"`
	Events          uint64    `json:"events"`
	Alerts          uint64    `json:"alerts"`
	Scanned         uint64    `json:"scanned"`
	Rules           int       `json:"rules"`
	Signatures      int       `json:"signatures"`
	ResponseEnabled bool      `json:"response_enabled"` // automatic kill/quarantine on
	RemoteCommands  bool      `json:"remote_commands"`  // agent accepts server commands
	SpoolBacklog    int       `json:"spool_backlog"`    // alerts waiting to upload
}

// Command types the agent understands.
const (
	CmdKill       = "kill"       // SIGKILL PID
	CmdQuarantine = "quarantine" // move Path into quarantine
	CmdScan       = "scan"       // signature-scan Path (file or directory)
)

// Command is a server-issued response action.
type Command struct {
	ID      string    `json:"id"`
	Type    string    `json:"type"`
	PID     int       `json:"pid,omitempty"`
	Path    string    `json:"path,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	AlertID string    `json:"alert_id,omitempty"`
	Created time.Time `json:"created"`
}

// HeartbeatResponse returns commands for the agent to run.
type HeartbeatResponse struct {
	ServerTime time.Time `json:"server_time"`
	Commands   []Command `json:"commands,omitempty"`
}

// CommandResult reports the outcome of a Command.
type CommandResult struct {
	HostID    string    `json:"host_id"`
	CommandID string    `json:"command_id"`
	OK        bool      `json:"ok"`
	Output    string    `json:"output,omitempty"`
	Error     string    `json:"error,omitempty"`
	Time      time.Time `json:"time"`
}
