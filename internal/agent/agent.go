// Package agent wires collectors, the signature scanner and the rule engine
// together and writes alerts.
package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/avaadrian/sbs/internal/anomaly"
	"github.com/avaadrian/sbs/internal/api"
	"github.com/avaadrian/sbs/internal/collector/ebpf"
	"github.com/avaadrian/sbs/internal/collector/fs"
	"github.com/avaadrian/sbs/internal/collector/proc"
	"github.com/avaadrian/sbs/internal/event"
	"github.com/avaadrian/sbs/internal/response"
	"github.com/avaadrian/sbs/internal/rules"
	"github.com/avaadrian/sbs/internal/scanner"
	"github.com/avaadrian/sbs/internal/transport"
	"gopkg.in/yaml.v3"
)

// severityRank orders severities for threshold comparisons.
var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Response modes.
const (
	ModeOff  = "off"  // never act automatically
	ModeAsk  = "ask"  // propose the action and wait for operator approval
	ModeAuto = "auto" // act immediately
)

// ResponseConfig controls automatic response actions.
type ResponseConfig struct {
	// Mode is off | ask | auto. If empty, Enabled is used for back-compat
	// (true => auto, false => off).
	Mode          string `yaml:"mode"`
	Enabled       bool   `yaml:"enabled"`
	MinSeverity   string `yaml:"min_severity"` // act/propose at or above this severity
	QuarantineDir string `yaml:"quarantine_dir"`
	// MaxAutoActionsPerMinute caps automatic kill/quarantine actions in auto
	// mode. When exceeded, the circuit breaker downgrades the agent to ask.
	// 0 (unset) uses the default of 10; a negative value disables the breaker.
	MaxAutoActionsPerMinute int `yaml:"max_auto_actions_per_minute"`
}

// mode returns the effective response mode.
func (r ResponseConfig) mode() string {
	switch r.Mode {
	case ModeOff, ModeAsk, ModeAuto:
		return r.Mode
	case "":
		if r.Enabled {
			return ModeAuto
		}
		return ModeOff
	default:
		return r.Mode // validated in New
	}
}

// ServerConfig points the agent at an sbs-server for alert upload and commands.
type ServerConfig struct {
	URL               string        `yaml:"url"`
	Insecure          bool          `yaml:"insecure"`
	Token             string        `yaml:"token"`
	SpoolDir          string        `yaml:"spool_dir"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	// CAFile is an optional PEM CA bundle used to verify the server's TLS
	// certificate, for a server with a private or self-signed CA.
	CAFile string `yaml:"ca_file"`
}

// AnomalyConfig controls the behavioral anomaly layer.
type AnomalyConfig struct {
	Enabled  bool   `yaml:"enabled"`
	StateDir string `yaml:"state_dir"`
}

// Config is the agent configuration file.
type Config struct {
	// ProcessSource is "auto" (ebpf if built, else netlink, else procfs),
	// "ebpf", "netlink" or "procfs".
	ProcessSource string        `yaml:"process_source"`
	PollInterval  time.Duration `yaml:"poll_interval"`
	Watch         []fs.Watch    `yaml:"watch"`
	// ScanOnExec scans the binary of every new process.
	ScanOnExec bool `yaml:"scan_on_exec"`
	// ScanOnWrite scans files written under watched paths.
	ScanOnWrite bool     `yaml:"scan_on_write"`
	ScanMaxSize int64    `yaml:"scan_max_size"`
	RulePaths   []string `yaml:"rules"`
	SigPaths    []string `yaml:"signatures"`
	// NoDefaults skips the built-in rules and signatures.
	NoDefaults bool   `yaml:"no_defaults"`
	AlertsPath string `yaml:"alerts"` // "-" or empty = stdout
	EventsPath string `yaml:"events"` // optional raw telemetry log
	// Dedup suppresses repeats of the same rule on the same process/file.
	Dedup time.Duration `yaml:"dedup"`

	Response ResponseConfig `yaml:"response"`
	Server   ServerConfig   `yaml:"server"`
	Anomaly  AnomalyConfig  `yaml:"anomaly"`
	// RemoteCommands lets the agent execute commands issued by the server.
	// Off by default: the server channel is trusted to report status, not to
	// drive kill/quarantine on the host without local opt-in.
	RemoteCommands bool `yaml:"remote_commands"`

	// Set by the program, not the YAML file.
	AgentVersion string `yaml:"-"`
}

// DefaultConfig is used when no config file is given.
func DefaultConfig() Config {
	return Config{
		ProcessSource: "auto",
		PollInterval:  100 * time.Millisecond,
		ScanOnExec:    true,
		ScanOnWrite:   true,
		ScanMaxSize:   scanner.DefaultMaxSize,
		Dedup:         5 * time.Second,
		Response:      ResponseConfig{Mode: ModeAsk, MinSeverity: "critical", QuarantineDir: "/var/lib/sbs/quarantine", MaxAutoActionsPerMinute: 10},
		Anomaly:       AnomalyConfig{Enabled: true, StateDir: "/var/lib/sbs"},
		Watch:         defaultWatch(),
	}
}

// LoadConfig reads a YAML config on top of the defaults.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Stats are counters exposed for monitoring and the benchmark.
type Stats struct {
	Events, Alerts, Scanned atomic.Uint64
}

// Agent is a running EDR agent.
type Agent struct {
	cfg     Config
	rules   atomic.Pointer[rules.Engine] // hot-swappable: read by Handle, replaced on rule reload
	scan    *scanner.Scanner
	alerts  io.Writer
	events  io.Writer
	mu      sync.Mutex
	dedup   map[string]time.Time
	self    int
	Stats   Stats
	Source  string
	closers []io.Closer

	actioner *response.Actioner
	anom     *anomaly.Detector
	trans    *transport.Client
	host     api.Host
	started  time.Time
	respMin  int        // severity rank threshold for response, -1 = disabled
	resp     *respState // live effective mode + auto-response circuit breaker

	// Built-in + file rules, kept so the engine can be rebuilt with custom
	// rules fetched from the server. Flattened; validated unique in New.
	builtins []*rules.Rule
	// Custom rule state, touched only on the heartbeat goroutine.
	rulesVersion string // version of the loaded custom rule set, "" if none
	rulesErr     string // last custom-rule load error, "" if none
}

// New builds an agent. defaultRules/defaultSigs are the built-in sets.
func New(cfg Config, defaultRules []*rules.Rule, defaultSigs func(*scanner.Scanner) error) (*Agent, error) {
	// builtins is every locally-sourced rule (defaults + configured files). It
	// is kept so the engine can be rebuilt as builtins + custom server rules.
	var builtins []*rules.Rule
	if !cfg.NoDefaults {
		builtins = append(builtins, defaultRules...)
	}
	for _, p := range cfg.RulePaths {
		rs, err := rules.LoadPath(p)
		if err != nil {
			return nil, err
		}
		builtins = append(builtins, rs...)
	}
	eng, err := rules.NewEngine(builtins)
	if err != nil {
		return nil, err
	}
	sc := scanner.New()
	if cfg.ScanMaxSize > 0 {
		sc.MaxSize = cfg.ScanMaxSize
	}
	if !cfg.NoDefaults {
		if err := defaultSigs(sc); err != nil {
			return nil, err
		}
	}
	for _, p := range cfg.SigPaths {
		if err := sc.AddPath(p); err != nil {
			return nil, err
		}
	}
	a := &Agent{cfg: cfg, scan: sc, dedup: map[string]time.Time{}, self: os.Getpid(),
		started: time.Now(), respMin: -1, builtins: builtins}
	a.rules.Store(eng)
	if a.alerts, err = a.open(cfg.AlertsPath); err != nil {
		return nil, err
	}
	if cfg.EventsPath != "" {
		if a.events, err = a.open(cfg.EventsPath); err != nil {
			return nil, err
		}
	}
	if cfg.Anomaly.Enabled {
		a.anom = anomaly.New(cfg.Anomaly.StateDir)
	}
	mode := cfg.Response.mode()
	switch mode {
	case ModeOff, ModeAsk, ModeAuto:
	default:
		return nil, fmt.Errorf("response.mode: unknown mode %q (want off|ask|auto)", mode)
	}
	maxAuto := cfg.Response.MaxAutoActionsPerMinute
	if maxAuto == 0 { // unset => default; negative explicitly disables the breaker
		maxAuto = 10
	}
	a.resp = newRespState(mode, maxAuto)
	// Build the actioner and severity threshold whenever response could ever
	// run: the configured mode is not off, or a server is present and may
	// override the mode to ask/auto at runtime. With no server and mode off,
	// the actioner stays nil and respond() is a no-op, exactly as before.
	if mode != ModeOff || cfg.Server.URL != "" {
		a.actioner = response.NewActioner()
		sev := cfg.Response.MinSeverity
		if sev == "" {
			sev = "critical"
		}
		r, ok := severityRank[sev]
		if !ok {
			return nil, fmt.Errorf("response.min_severity: unknown severity %q", cfg.Response.MinSeverity)
		}
		a.respMin = r
	}
	if cfg.Server.URL != "" {
		a.host = gatherHost(cfg)
		spool := cfg.Server.SpoolDir
		if spool == "" {
			spool = "/var/lib/sbs/spool"
		}
		a.trans, err = transport.New(transport.Config{
			ServerURL: cfg.Server.URL, Token: cfg.Server.Token, Host: a.host,
			SpoolDir: spool, HeartbeatInterval: cfg.Server.HeartbeatInterval, Insecure: cfg.Server.Insecure,
			CAFile: cfg.Server.CAFile,
		})
		if err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (a *Agent) open(path string) (io.Writer, error) {
	if path == "" || path == "-" {
		return os.Stdout, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	a.closers = append(a.closers, f)
	return f, nil
}

// Rules returns the number of active rules; Signatures the loaded signature counts.
func (a *Agent) Rules() int                     { return a.rules.Load().Len() }
func (a *Agent) Signatures() (hashes, strs int) { return a.scan.Count() }

// Run starts all collectors and processes events until ctx is cancelled.
// ready is called once every collector is listening.
func (a *Agent) Run(ctx context.Context, ready func()) error {
	defer func() {
		for _, c := range a.closers {
			c.Close()
		}
	}()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	events := make(chan *event.Event, 4096)
	errc := make(chan error, 2)
	skip := func(pid int) bool { return pid == a.self }

	switch src := a.cfg.ProcessSource; src {
	case "", "auto":
		// Prefer eBPF (fewest missed short-lived processes), then netlink, then
		// polling. eBPF is only present when built with -tags ebpf; when it is
		// not, Open returns ErrNotBuilt and we skip it silently.
		if c, err := ebpf.Open(); err == nil {
			a.Source = "ebpf"
			a.closers = append(a.closers, c)
			go func() { errc <- c.Run(ctx, events, skip) }()
			break
		} else if !errors.Is(err, ebpf.ErrNotBuilt) {
			log.Printf("agent: ebpf collector unavailable: %v", err)
		}
		nl, err := proc.OpenNetlink()
		if err == nil {
			a.Source = "netlink"
			go func() { errc <- nl.Run(ctx, events, skip) }()
			break
		}
		log.Printf("agent: %v; falling back to procfs polling", err)
		fallthrough
	case "procfs":
		a.Source = "procfs"
		p := &proc.Poller{Interval: a.cfg.PollInterval}
		go func() { errc <- p.Run(ctx, events, skip) }()
	case "netlink":
		nl, err := proc.OpenNetlink()
		if err != nil {
			return err
		}
		a.Source = "netlink"
		go func() { errc <- nl.Run(ctx, events, skip) }()
	case "ebpf":
		c, err := ebpf.Open()
		if err != nil {
			return err
		}
		a.Source = "ebpf"
		a.closers = append(a.closers, c)
		go func() { errc <- c.Run(ctx, events, skip) }()
	default:
		return fmt.Errorf("unknown process_source %q", src)
	}

	if len(a.cfg.Watch) > 0 {
		w, err := fs.New(a.cfg.Watch)
		if err != nil {
			return err
		}
		go func() { errc <- w.Run(ctx, events) }()
	}
	if a.trans != nil {
		a.host.ProcessSource = a.Source
		go func() { a.trans.Run(ctx) }()
		go a.heartbeatLoop(ctx)
	}
	if ready != nil {
		ready()
	}
	for {
		select {
		case <-ctx.Done():
			if a.anom != nil {
				a.anom.Save()
			}
			return nil
		case err := <-errc:
			if err != nil {
				return err
			}
		case ev := <-events:
			a.Handle(ev)
		}
	}
}

// Handle enriches one event, scans it, evaluates rules and emits alerts.
func (a *Agent) Handle(ev *event.Event) {
	a.Stats.Events.Add(1)
	var alerts []*event.Alert
	switch {
	case ev.Process != nil && a.cfg.ScanOnExec && ev.Process.Exe != "":
		alerts = append(alerts, a.scanPath(strings.TrimSuffix(ev.Process.Exe, " (deleted)"), ev, nil)...)
	case ev.File != nil && a.cfg.ScanOnWrite && (ev.File.Op == "modify" || ev.File.Op == "rename"):
		alerts = append(alerts, a.scanPath(ev.File.Path, ev, &ev.File.SHA256)...)
	}
	if a.events != nil {
		a.write(a.events, ev)
	}
	alerts = append(alerts, a.rules.Load().Evaluate(ev)...)
	if a.anom != nil {
		if al := a.anom.Observe(ev); al != nil {
			alerts = append(alerts, al)
		}
	}
	for _, al := range alerts {
		if a.suppress(al) {
			continue
		}
		al.ID = newID()
		al.Host = a.host.ID
		a.respond(al)
		a.Stats.Alerts.Add(1)
		a.write(a.alerts, al)
		if a.trans != nil {
			a.trans.Enqueue(al)
		}
	}
}

// respond handles an alert at or above the configured severity threshold, using
// the current effective mode (which the server can override at runtime). In
// auto mode it executes the response actions and records the outcomes; in ask
// mode it only records which actions it proposes, leaving execution to an
// operator approval (delivered back as a server command). The auto-response
// circuit breaker can downgrade auto to ask mid-stream: when executing an
// alert's actions would exceed the per-minute cap, this and later alerts are
// handled as proposals instead.
func (a *Agent) respond(al *event.Alert) {
	mode := a.resp.mode()
	if a.actioner == nil || mode == ModeOff || a.respMin < 0 || severityRank[al.Severity] < a.respMin {
		return
	}
	actions := proposedActions(al) // ordered list of {type, target}
	if mode == ModeAuto {
		if ok, tripped := a.resp.reserveAuto(len(actions), time.Now()); ok {
			for _, act := range actions {
				switch act.kind {
				case api.CmdKill:
					al.Actions = append(al.Actions, a.actioner.Kill(act.pid))
				case api.CmdQuarantine:
					al.Actions = append(al.Actions, a.actioner.Quarantine(act.path, a.cfg.Response.QuarantineDir))
				}
			}
			return
		} else if tripped {
			log.Printf("agent: auto-response circuit breaker tripped (> %d actions/min): downgrading to ask",
				a.resp.maxPerMin)
		}
		// Breaker is tripped: fall through and handle this alert as a proposal.
	}
	for _, act := range actions {
		al.Proposed = append(al.Proposed, act.kind)
	}
}

type respAction struct {
	kind string // api.CmdKill | api.CmdQuarantine
	pid  int
	path string
}

// proposedActions is the response plan for an alert: kill the process (and
// quarantine its binary when the hit was a signature match), or quarantine the
// written file. The server derives the same plan when an operator approves.
func proposedActions(al *event.Alert) []respAction {
	var out []respAction
	if p := al.Event.Process; p != nil && p.PID > 0 {
		out = append(out, respAction{kind: api.CmdKill, pid: p.PID})
		if al.Signature != "" && p.Exe != "" {
			out = append(out, respAction{kind: api.CmdQuarantine, path: strings.TrimSuffix(p.Exe, " (deleted)")})
		}
		return out
	}
	if f := al.Event.File; f != nil && f.Path != "" {
		out = append(out, respAction{kind: api.CmdQuarantine, path: f.Path})
	}
	return out
}

func (a *Agent) scanPath(path string, ev *event.Event, sha *string) []*event.Alert {
	h, ms, err := a.scan.ScanFile(path)
	if err != nil {
		return nil
	}
	a.Stats.Scanned.Add(1)
	if sha != nil {
		*sha = h
	}
	var out []*event.Alert
	for _, m := range ms {
		out = append(out, &event.Alert{
			Time:      time.Now().UTC(),
			RuleID:    "SBS-AV-" + strings.ToUpper(m.Kind),
			Title:     "Malware signature match: " + m.Signature + " in " + path,
			Severity:  m.Severity,
			MITRE:     []string{"T1204"},
			Signature: m.Signature,
			Event:     ev,
		})
	}
	return out
}

func (a *Agent) suppress(al *event.Alert) bool {
	if a.cfg.Dedup <= 0 {
		return false
	}
	key := al.RuleID + "|" + al.Signature + "|"
	if p := al.Event.Process; p != nil {
		key += fmt.Sprintf("pid:%d:%s", p.PID, p.Exe)
	}
	if f := al.Event.File; f != nil {
		key += "file:" + f.Path
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if t, ok := a.dedup[key]; ok && now.Sub(t) < a.cfg.Dedup {
		return true
	}
	a.dedup[key] = now
	if len(a.dedup) > 10000 {
		for k, t := range a.dedup {
			if now.Sub(t) >= a.cfg.Dedup {
				delete(a.dedup, k)
			}
		}
	}
	return false
}

func newID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (a *Agent) write(w io.Writer, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	a.mu.Lock()
	w.Write(append(b, '\n'))
	a.mu.Unlock()
}
