// Package proc collects process execution events on Linux.
package proc

import (
	"bytes"
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/avaadrian/sbs/internal/event"
)

// ProcRoot is the procfs mount point.
var ProcRoot = "/proc"

// Read builds a process record from /proc/<pid>. It returns nil if the
// process is gone or is a kernel thread.
func Read(pid int) *event.Process {
	dir := ProcRoot + "/" + strconv.Itoa(pid)
	cmd, err := os.ReadFile(dir + "/cmdline")
	if err != nil || len(cmd) == 0 {
		return nil // exited, or kernel thread
	}
	p := &event.Process{PID: pid, Cmdline: cmdline(cmd)}
	p.Exe, _ = os.Readlink(dir + "/exe")
	p.Cwd, _ = os.Readlink(dir + "/cwd")
	p.Comm = readComm(dir)
	p.PPID, p.UID = status(dir)
	var r0, r1 string
	p.Stdin, r0 = fdType(dir, "0")
	p.Stdout, r1 = fdType(dir, "1")
	if p.Remote = r0; p.Remote == "" {
		p.Remote = r1
	}
	if p.PPID > 0 {
		pdir := ProcRoot + "/" + strconv.Itoa(p.PPID)
		p.ParentExe, _ = os.Readlink(pdir + "/exe")
		p.ParentComm = readComm(pdir)
		if b, err := os.ReadFile(pdir + "/cmdline"); err == nil {
			p.ParentCmdline = cmdline(b)
		}
	}
	return p
}

// NewEvent wraps a process record in an event.
func NewEvent(p *event.Process, source string) *event.Event {
	return &event.Event{Time: time.Now().UTC(), Type: event.TypeProcess, Source: source, Process: p}
}

func cmdline(b []byte) string {
	b = bytes.TrimRight(b, "\x00")
	return string(bytes.ReplaceAll(b, []byte{0}, []byte{' '}))
}

func readComm(dir string) string {
	b, _ := os.ReadFile(dir + "/comm")
	return strings.TrimSpace(string(b))
}

func status(dir string) (ppid, uid int) {
	b, err := os.ReadFile(dir + "/status")
	if err != nil {
		return 0, -1
	}
	uid = -1
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		switch k {
		case "PPid":
			ppid, _ = strconv.Atoi(f[0])
		case "Uid":
			uid, _ = strconv.Atoi(f[0])
		}
	}
	return ppid, uid
}

// fdType classifies a file descriptor. Sockets are "inet" when they are
// TCP/UDP (remote is then the peer address) and "socket" otherwise (Unix
// domain, as used by sshd and service managers).
func fdType(dir, fd string) (typ, remote string) {
	t, err := os.Readlink(dir + "/fd/" + fd)
	switch {
	case err != nil:
		return "none", ""
	case strings.HasPrefix(t, "socket:["):
		inode := strings.TrimSuffix(strings.TrimPrefix(t, "socket:["), "]")
		if r, ok := inetPeer(dir, inode); ok {
			return "inet", r
		}
		return "socket", ""
	case strings.HasPrefix(t, "pipe:"):
		return "pipe", ""
	case t == "/dev/null":
		return "null", ""
	case strings.HasPrefix(t, "/dev/pts/"), strings.HasPrefix(t, "/dev/tty"), t == "/dev/console":
		return "tty", ""
	}
	return "file", ""
}

// inetPeer looks a socket inode up in the process's network namespace tables.
func inetPeer(dir, inode string) (string, bool) {
	for _, tbl := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, err := os.ReadFile(dir + "/net/" + tbl)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) > 9 && f[9] == inode {
				return decodeAddr(f[2]), true
			}
		}
	}
	return "", false
}

// decodeAddr turns /proc/net "0100007F:1F90" into "127.0.0.1:8080".
func decodeAddr(s string) string {
	h, port, ok := strings.Cut(s, ":")
	if !ok {
		return s
	}
	pn, _ := strconv.ParseUint(port, 16, 16)
	raw, err := hex.DecodeString(h)
	if err != nil {
		return s
	}
	// Each 32-bit word is in host (little-endian) order.
	for i := 0; i+4 <= len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	ip := net.IP(raw)
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return net.JoinHostPort(ip.String(), strconv.FormatUint(pn, 10))
}

// startTime returns field 22 of /proc/<pid>/stat, used to tell PID reuse apart.
func startTime(pid int) string {
	b, err := os.ReadFile(ProcRoot + "/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return ""
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return ""
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return ""
	}
	return f[19]
}
