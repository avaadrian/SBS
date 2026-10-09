// Package event defines the telemetry records produced by collectors and the
// alerts produced by detections.
package event

import (
	"strconv"
	"strings"
	"time"
)

// Event types.
const (
	TypeProcess = "process"
	TypeFile    = "file"
)

// Event is a single piece of host telemetry.
type Event struct {
	Time    time.Time `json:"time"`
	Type    string    `json:"type"`
	Source  string    `json:"source"`
	Process *Process  `json:"process,omitempty"`
	File    *File     `json:"file,omitempty"`
}

// Process describes a process execution.
type Process struct {
	PID           int    `json:"pid"`
	PPID          int    `json:"ppid"`
	PGID          int    `json:"pgid"`
	SID           int    `json:"sid"`
	UID           int    `json:"uid"`
	Exe           string `json:"exe"`
	Comm          string `json:"comm"`
	Cmdline       string `json:"cmdline"`
	Cwd           string `json:"cwd"`
	Stdin         string `json:"stdin"`            // inet, socket, pipe, tty, file, null, none
	Stdout        string `json:"stdout"`           // same values as Stdin
	Remote        string `json:"remote,omitempty"` // peer address when stdin/stdout is inet
	ParentExe     string `json:"parent_exe"`
	ParentComm    string `json:"parent_comm"`
	ParentCmdline string `json:"parent_cmdline"`
}

// File describes a filesystem change.
type File struct {
	Path   string `json:"path"`
	Op     string `json:"op"` // create, modify, delete, chmod, rename
	Tag    string `json:"tag,omitempty"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// Fields flattens the event into dotted field names used by detection rules.
func (e *Event) Fields() map[string]string {
	f := map[string]string{"event.type": e.Type, "event.source": e.Source}
	if p := e.Process; p != nil {
		f["process.pid"] = strconv.Itoa(p.PID)
		f["process.ppid"] = strconv.Itoa(p.PPID)
		f["process.pgid"] = strconv.Itoa(p.PGID)
		f["process.sid"] = strconv.Itoa(p.SID)
		f["process.uid"] = strconv.Itoa(p.UID)
		f["process.exe"] = p.Exe
		f["process.name"] = p.Comm
		f["process.cmdline"] = p.Cmdline
		f["process.cwd"] = p.Cwd
		f["process.stdin"] = p.Stdin
		f["process.stdout"] = p.Stdout
		f["process.remote"] = p.Remote
		f["parent.exe"] = p.ParentExe
		f["parent.name"] = p.ParentComm
		f["parent.cmdline"] = p.ParentCmdline
	}
	if fl := e.File; fl != nil {
		f["file.path"] = fl.Path
		f["file.name"] = fl.Path[strings.LastIndex(fl.Path, "/")+1:]
		f["file.op"] = fl.Op
		f["file.tag"] = fl.Tag
		f["file.size"] = strconv.FormatInt(fl.Size, 10)
		f["file.mode"] = fl.Mode
		f["file.sha256"] = fl.SHA256
	}
	return f
}

// Alert is a detection raised by a rule or by the signature scanner.
type Alert struct {
	ID        string    `json:"id"`             // random, assigned by the agent; used for idempotent upload
	Host      string    `json:"host,omitempty"` // host ID, filled in by the server or transport
	Time      time.Time `json:"time"`
	RuleID    string    `json:"rule_id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	MITRE     []string  `json:"mitre,omitempty"`
	Signature string    `json:"signature,omitempty"`
	Event     *Event    `json:"event"`
	// Actions are automatic response actions the agent took for this alert.
	Actions []ActionResult `json:"actions,omitempty"`
	// Proposed lists response action types ("kill", "quarantine") the agent
	// would take but is holding for approval (ask mode). Empty in auto/off mode.
	Proposed []string `json:"proposed,omitempty"`
}

// ActionResult records one response action (kill, quarantine, ...).
type ActionResult struct {
	Action string    `json:"action"` // kill | quarantine
	Target string    `json:"target"` // pid or path
	OK     bool      `json:"ok"`
	Error  string    `json:"error,omitempty"`
	Detail string    `json:"detail,omitempty"` // e.g. quarantine location
	Time   time.Time `json:"time"`
}
