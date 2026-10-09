package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/avaadrian/sbs/internal/api"
	"github.com/avaadrian/sbs/internal/rules"
	"github.com/avaadrian/sbs/internal/scanner"
)

// gatherHost builds the host identity reported to the server. The ID is stable
// across restarts: /etc/machine-id when readable, otherwise a random ID
// persisted next to the agent state.
func gatherHost(cfg Config) api.Host {
	h := api.Host{
		Arch:         runtime.GOARCH,
		AgentVersion: cfg.AgentVersion,
	}
	h.Hostname, _ = os.Hostname()
	h.OS = osPretty()
	h.Kernel = strings.TrimSpace(readFile("/proc/sys/kernel/osrelease"))
	h.IPs = localIPs()
	h.ID = hostID(cfg)
	h.ResponseMode = cfg.Response.mode()
	return h
}

func hostID(cfg Config) string {
	if id := strings.TrimSpace(readFile("/etc/machine-id")); id != "" {
		sum := sha256.Sum256([]byte("sbs:" + id))
		return hex.EncodeToString(sum[:8])
	}
	// Fall back to a persisted random ID.
	dir := cfg.Anomaly.StateDir
	if dir == "" {
		dir = "/var/lib/sbs"
	}
	path := dir + "/host-id"
	if id := strings.TrimSpace(readFile(path)); id != "" {
		return id
	}
	id := newID()
	if os.MkdirAll(dir, 0o700) == nil {
		os.WriteFile(path, []byte(id+"\n"), 0o600)
	}
	return id
}

func osPretty() string {
	for _, line := range strings.Split(readFile("/etc/os-release"), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return runtime.GOOS
}

func localIPs() []string {
	var out []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() {
			out = append(out, ipn.IP.String())
		}
	}
	return out
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// heartbeatLoop periodically reports status to the server and runs any
// commands it returns (when RemoteCommands is enabled).
func (a *Agent) heartbeatLoop(ctx context.Context) {
	iv := a.cfg.Server.HeartbeatInterval
	if iv <= 0 {
		iv = 30 * time.Second
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.sendHeartbeat(ctx)
		}
	}
}

func (a *Agent) sendHeartbeat(ctx context.Context) {
	hashes, strs := a.Signatures()
	mode := a.resp.mode()
	// Report the current effective mode, not the configured one, so the console
	// shows reality. a.host is written once before the goroutines start, so this
	// value copy is race-free.
	host := a.host
	host.ResponseMode = mode
	hb := api.Heartbeat{
		Host:                host,
		Time:                time.Now().UTC(),
		UptimeSeconds:       time.Since(a.started).Seconds(),
		Events:              a.Stats.Events.Load(),
		Alerts:              a.Stats.Alerts.Load(),
		Scanned:             a.Stats.Scanned.Load(),
		Rules:               a.Rules(),
		Signatures:          hashes + strs,
		ResponseEnabled:     a.actioner != nil && mode != ModeOff,
		RemoteCommands:      a.cfg.RemoteCommands,
		SpoolBacklog:        a.trans.Backlog(),
		RulesVersion:        a.rulesVersion,
		RulesError:          a.rulesErr,
		AutoResponseTripped: a.resp.breakerTripped(),
	}
	resp, err := a.trans.Heartbeat(ctx, hb)
	if err != nil || resp == nil {
		return
	}
	a.applyResponseMode(resp.ResponseMode)
	a.reloadRules(ctx, resp.RulesVersion)
	for _, cmd := range resp.Commands {
		a.runCommand(ctx, cmd)
	}
}

// applyResponseMode applies a server-sent effective-mode override (off|ask|auto),
// reverting to the configured mode when empty. A non-empty override also clears
// the auto-response circuit breaker. It logs any change.
func (a *Agent) applyResponseMode(mode string) {
	if mode != "" {
		switch mode {
		case ModeOff, ModeAsk, ModeAuto:
		default:
			log.Printf("agent: ignoring invalid server response mode %q", mode)
			return
		}
	}
	from, to, changed := a.resp.applyOverride(mode)
	if !changed {
		return
	}
	if mode == "" {
		log.Printf("agent: response mode %s -> %s (server override cleared)", from, to)
	} else {
		log.Printf("agent: response mode %s -> %s (server override)", from, to)
	}
}

// reloadRules fetches and hot-swaps the custom rule set when the server reports
// a version the agent does not have loaded. On any fetch/parse/compile failure
// the current engine is kept and the error is remembered for the next heartbeat.
// It runs only on the heartbeat goroutine, so rulesVersion/rulesErr are unguarded.
func (a *Agent) reloadRules(ctx context.Context, serverVersion string) {
	if serverVersion == a.rulesVersion {
		return // up to date (covers both empty)
	}
	rs, err := a.trans.FetchRules(ctx)
	if err != nil {
		a.rulesErr = err.Error()
		return
	}
	custom, err := rules.Parse([]byte(rs.YAML), "server rules "+rs.Version)
	if err != nil {
		a.rulesErr = err.Error()
		return
	}
	eng, err := rules.NewEngine(a.builtins, custom)
	if err != nil {
		a.rulesErr = err.Error()
		return
	}
	a.rules.Store(eng)
	a.rulesVersion = rs.Version
	a.rulesErr = ""
	log.Printf("agent: loaded custom rule set version %q (%d custom rules, %d active total)",
		rs.Version, len(custom), eng.Len())
}

// runCommand executes a server-issued command and reports the result. When
// RemoteCommands is disabled it reports the command as refused rather than
// silently dropping it, so the console sees why nothing happened.
func (a *Agent) runCommand(ctx context.Context, cmd api.Command) {
	res := api.CommandResult{HostID: a.host.ID, CommandID: cmd.ID, Time: time.Now().UTC()}
	// kill/quarantine are accepted when remote commands are on, or in ask mode
	// (where such a command is the operator's approval of the agent's own
	// proposal). scan is only ever accepted with remote commands enabled.
	approval := a.resp.mode() == ModeAsk && (cmd.Type == api.CmdKill || cmd.Type == api.CmdQuarantine)
	if !a.cfg.RemoteCommands && !approval {
		res.Error = "remote commands disabled on agent"
		a.trans.CommandResult(ctx, res)
		return
	}
	switch cmd.Type {
	case api.CmdKill:
		if a.actioner == nil {
			res.Error = "response actions disabled on agent"
			break
		}
		r := a.actioner.Kill(cmd.PID)
		res.OK, res.Error, res.Output = r.OK, r.Error, r.Detail
	case api.CmdQuarantine:
		if a.actioner == nil {
			res.Error = "response actions disabled on agent"
			break
		}
		r := a.actioner.Quarantine(cmd.Path, a.cfg.Response.QuarantineDir)
		res.OK, res.Error, res.Output = r.OK, r.Error, r.Detail
	case api.CmdScan:
		n, hits := a.scanCommand(cmd.Path)
		res.OK = true
		res.Output = fmtScan(n, hits)
	default:
		res.Error = "unknown command type " + cmd.Type
	}
	a.trans.CommandResult(ctx, res)
}

func (a *Agent) scanCommand(root string) (files int, hits []scanner.Match) {
	n, _ := a.scan.ScanTree(root, func(m scanner.Match) { hits = append(hits, m) })
	return n, hits
}

func fmtScan(files int, hits []scanner.Match) string {
	b := &strings.Builder{}
	b.WriteString("scanned ")
	b.WriteString(itoa(files))
	b.WriteString(" files, ")
	b.WriteString(itoa(len(hits)))
	b.WriteString(" detections")
	for _, m := range hits {
		b.WriteString("\n  ")
		b.WriteString(m.Signature)
		b.WriteString(" ")
		b.WriteString(m.Path)
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
