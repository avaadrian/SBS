package bench

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/avaadrian/sbs/internal/event"
)

// Options configure a benchmark run.
type Options struct {
	AgentPath string
	Source    string        // process source passed to the agent ("" = auto)
	Timeout   time.Duration // how long to wait for each detection
	LoadExecs int           // processes spawned in the exec-burst phase
	Only      string        // run only scenarios whose name contains this
	Keep      bool          // keep the sandbox directory
	Heldout   bool          // use the held-out scenario set instead of the built-in one
	Log       io.Writer
}

// Result is the outcome of one scenario.
type Result struct {
	Name      string   `json:"name"`
	Technique string   `json:"technique"`
	Tactic    string   `json:"tactic"`
	Detected  bool     `json:"detected"`
	LatencyMS float64  `json:"latency_ms,omitempty"`
	Matched   string   `json:"matched,omitempty"`
	Alerts    []string `json:"alerts,omitempty"` // every rule/signature that fired
	Error     string   `json:"error,omitempty"`
}

// Report is the full benchmark output.
type Report struct {
	Time            time.Time `json:"time"`
	Host            string    `json:"host"`
	Kernel          string    `json:"kernel"`
	Source          string    `json:"process_source"`
	Suite           string    `json:"suite"` // "builtin" or "heldout"
	Scenarios       []Result  `json:"scenarios"`
	Detected        int       `json:"detected"`
	Total           int       `json:"total"`
	DetectionRate   float64   `json:"detection_rate"`
	MedianLatencyMS float64   `json:"median_latency_ms"`
	FalsePositives  []string  `json:"false_positives"`
	BenignCommands  int       `json:"benign_commands"`
	LoadExecs       int       `json:"load_execs"`
	LoadSeen        int       `json:"load_seen"`
	LoadVisibility  float64   `json:"load_visibility"`
	LoadDuration    float64   `json:"load_duration_s"`
	CPUAvgPct       float64   `json:"cpu_avg_pct"`
	CPUPeakPct      float64   `json:"cpu_peak_pct"`
	RSSPeakMB       float64   `json:"rss_peak_mb"`
	AgentEvents     int       `json:"agent_events"`
	AgentScanned    int       `json:"agent_scanned"`
}

type seenAlert struct {
	at time.Time
	a  event.Alert
}

// Run executes the benchmark end to end.
func Run(o Options) (*Report, error) {
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	root, err := os.MkdirTemp("/tmp", "sbs-bench-")
	if err != nil {
		return nil, err
	}
	if !o.Keep {
		defer os.RemoveAll(root)
	}
	sb := &Sandbox{Root: root}
	for _, d := range []string{"cron", "drop", "etc", "home/.ssh"} {
		if err := os.MkdirAll(sb.Dir(d), 0o755); err != nil {
			return nil, err
		}
	}
	// The benchmark measures detection, so disable automatic response and the
	// anomaly layer's persistent state (it would otherwise learn across runs).
	cfg := fmt.Sprintf(`process_source: %q
alerts: %s
events: %s
dedup: 2s
response:
  mode: "off"
anomaly:
  enabled: false
watch:
  - {path: %s, tag: persistence}
  - {path: %s, tag: drop}
  - {path: %s, tag: ssh}
  - {path: %s, tag: preload}
`, orDefault(o.Source, "auto"), sb.Dir("alerts.jsonl"), sb.Dir("events.jsonl"),
		sb.Dir("cron"), sb.Dir("drop"), sb.Dir("home/.ssh"), sb.Dir("etc/ld.so.preload"))
	if err := os.WriteFile(sb.Dir("agent.yaml"), []byte(cfg), 0o644); err != nil {
		return nil, err
	}

	// Start the agent.
	logf, err := os.Create(sb.Dir("agent.log"))
	if err != nil {
		return nil, err
	}
	defer logf.Close()
	agent := exec.Command(o.AgentPath, "run", "-config", sb.Dir("agent.yaml"), "-ready-file", sb.Dir("ready"))
	agent.Stdout, agent.Stderr = logf, logf
	if err := agent.Start(); err != nil {
		return nil, fmt.Errorf("start agent: %w", err)
	}
	agentDone := make(chan struct{})
	go func() { agent.Wait(); close(agentDone) }()
	defer func() {
		agent.Process.Signal(syscall.SIGTERM)
		select {
		case <-agentDone:
		case <-time.After(5 * time.Second):
			agent.Process.Kill()
		}
	}()
	rep := &Report{Time: time.Now().UTC(), Host: hostname(), Kernel: kernel()}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if b, err := os.ReadFile(sb.Dir("ready")); err == nil {
			rep.Source = string(b)
			break
		}
		select {
		case <-agentDone:
			log, _ := os.ReadFile(sb.Dir("agent.log"))
			return nil, fmt.Errorf("agent exited during startup:\n%s", log)
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("agent not ready after 10s")
		}
	}
	fmt.Fprintf(o.Log, "agent running (pid %d, source %s), sandbox %s\n", agent.Process.Pid, rep.Source, root)

	tail := newTailer(sb.Dir("alerts.jsonl"))
	defer tail.stop()
	mon := startMonitor(agent.Process.Pid)

	// Phase 1: benign workload -> false positives.
	fmt.Fprintf(o.Log, "benign workload ... ")
	t0 := time.Now()
	n, err := Benign(sb)
	if err != nil {
		return nil, fmt.Errorf("benign workload: %w", err)
	}
	rep.BenignCommands = n
	time.Sleep(time.Second)
	for _, s := range tail.since(t0) {
		rep.FalsePositives = append(rep.FalsePositives, s.a.RuleID+" "+describe(&s.a))
	}
	fmt.Fprintf(o.Log, "%d false positives\n", len(rep.FalsePositives))
	clearDir(sb.Dir("drop"))

	// Phase 2: attack scenarios.
	scenarioSet := Scenarios()
	rep.Suite = "builtin"
	if o.Heldout {
		scenarioSet = HeldoutScenarios()
		rep.Suite = "heldout"
	}
	var lat []float64
	for _, sc := range scenarioSet {
		if o.Only != "" && !strings.Contains(sc.Name, o.Only) {
			continue
		}
		r := Result{Name: sc.Name, Technique: sc.Technique, Tactic: sc.Tactic}
		start := time.Now()
		if err := sc.Run(sb); err != nil {
			r.Error = err.Error()
		}
		end := time.Now().Add(o.Timeout)
		for time.Now().Before(end) && !r.Detected {
			for _, s := range tail.since(start) {
				if key, ok := matches(&s.a, sc.Expect); ok {
					r.Detected, r.Matched = true, key
					r.LatencyMS = float64(s.a.Time.Sub(start).Microseconds()) / 1000
					break
				}
			}
			if !r.Detected {
				time.Sleep(25 * time.Millisecond)
			}
		}
		time.Sleep(200 * time.Millisecond) // let related alerts land before listing them
		seen := map[string]bool{}
		for _, s := range tail.since(start) {
			k := s.a.RuleID
			if s.a.Signature != "" {
				k = "sig:" + s.a.Signature
			}
			if !seen[k] {
				seen[k] = true
				r.Alerts = append(r.Alerts, k)
			}
		}
		status := "MISSED"
		if r.Detected {
			status = fmt.Sprintf("detected in %.0fms by %s", r.LatencyMS, r.Matched)
			lat = append(lat, r.LatencyMS)
			rep.Detected++
		}
		fmt.Fprintf(o.Log, "  %-26s %-10s %s\n", sc.Name, sc.Technique, status)
		rep.Scenarios = append(rep.Scenarios, r)
		tail.drain()
	}
	rep.Total = len(rep.Scenarios)
	if rep.Total > 0 {
		rep.DetectionRate = float64(rep.Detected) / float64(rep.Total)
	}
	rep.MedianLatencyMS = median(lat)

	// Phase 3: exec burst -> how many short-lived processes the agent sees.
	if o.LoadExecs > 0 {
		fmt.Fprintf(o.Log, "exec burst (%d processes) ... ", o.LoadExecs)
		t := time.Now()
		marker := fmt.Sprintf("sbs-load-%d", t.UnixNano())
		for i := 0; i < o.LoadExecs; i++ {
			exec.Command("/bin/sh", "-c", "exit 0", fmt.Sprintf("%s-%d", marker, i)).Run()
		}
		rep.LoadDuration = time.Since(t).Seconds()
		time.Sleep(time.Second)
		rep.LoadExecs = o.LoadExecs
		rep.LoadSeen = countLines(sb.Dir("events.jsonl"), marker)
		rep.LoadVisibility = float64(rep.LoadSeen) / float64(rep.LoadExecs)
		fmt.Fprintf(o.Log, "agent saw %d (%.1f%%)\n", rep.LoadSeen, 100*rep.LoadVisibility)
	}

	rep.CPUAvgPct, rep.CPUPeakPct, rep.RSSPeakMB = mon.stop()

	agent.Process.Signal(syscall.SIGTERM)
	select {
	case <-agentDone:
	case <-time.After(5 * time.Second):
	}
	if b, err := os.ReadFile(sb.Dir("agent.log")); err == nil {
		if m := regexp.MustCompile(`events=(\d+) scanned=(\d+)`).FindSubmatch(b); m != nil {
			rep.AgentEvents, _ = strconv.Atoi(string(m[1]))
			rep.AgentScanned, _ = strconv.Atoi(string(m[2]))
		}
	}
	return rep, nil
}

func matches(a *event.Alert, expect []string) (string, bool) {
	for _, e := range expect {
		if sig, ok := strings.CutPrefix(e, "sig:"); ok {
			if a.Signature == sig {
				return e, true
			}
		} else if a.RuleID == e {
			return e, true
		}
	}
	return "", false
}

func describe(a *event.Alert) string {
	if p := a.Event.Process; p != nil {
		return fmt.Sprintf("(%s) %s", a.Title, p.Cmdline)
	}
	if f := a.Event.File; f != nil {
		return fmt.Sprintf("(%s) %s %s", a.Title, f.Op, f.Path)
	}
	return a.Title
}

// tailer follows the agent's alert file.
type tailer struct {
	mu     sync.Mutex
	alerts []seenAlert
	done   chan struct{}
}

func newTailer(path string) *tailer {
	t := &tailer{done: make(chan struct{})}
	go func() {
		var f *os.File
		var rd *bufio.Reader
		var partial string
		for {
			select {
			case <-t.done:
				if f != nil {
					f.Close()
				}
				return
			case <-time.After(20 * time.Millisecond):
			}
			if f == nil {
				var err error
				if f, err = os.Open(path); err != nil {
					f = nil
					continue
				}
				rd = bufio.NewReader(f)
			}
			for {
				line, err := rd.ReadString('\n')
				if err != nil {
					partial += line
					break
				}
				line, partial = partial+line, ""
				var a event.Alert
				if json.Unmarshal([]byte(line), &a) == nil {
					t.mu.Lock()
					t.alerts = append(t.alerts, seenAlert{at: time.Now(), a: a})
					t.mu.Unlock()
				}
			}
		}
	}()
	return t
}

// since returns alerts generated at or after t (by the agent's clock).
func (t *tailer) since(at time.Time) []seenAlert {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []seenAlert
	for _, s := range t.alerts {
		if !s.a.Time.Before(at) {
			out = append(out, s)
		}
	}
	return out
}

func (t *tailer) drain() {
	t.mu.Lock()
	t.alerts = nil
	t.mu.Unlock()
}

func (t *tailer) stop() { close(t.done) }

// monitor samples the agent's CPU and memory from /proc.
type monitor struct {
	done chan struct{}
	res  chan [3]float64
}

func startMonitor(pid int) *monitor {
	m := &monitor{done: make(chan struct{}), res: make(chan [3]float64, 1)}
	go func() {
		const hz = 100.0 // USER_HZ
		start := time.Now()
		first := cpuTicks(pid)
		prev, prevT := first, start
		var peakCPU, peakRSS float64
		tk := time.NewTicker(250 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-m.done:
				now := time.Now()
				last := cpuTicks(pid)
				avg := 100 * (last - first) / hz / now.Sub(start).Seconds()
				m.res <- [3]float64{avg, peakCPU, peakRSS}
				return
			case now := <-tk.C:
				c := cpuTicks(pid)
				if pct := 100 * (c - prev) / hz / now.Sub(prevT).Seconds(); pct > peakCPU {
					peakCPU = pct
				}
				prev, prevT = c, now
				if r := rssMB(pid); r > peakRSS {
					peakRSS = r
				}
			}
		}
	}()
	return m
}

func (m *monitor) stop() (avg, peak, rss float64) {
	close(m.done)
	r := <-m.res
	return r[0], r[1], r[2]
}

func cpuTicks(pid int) float64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	if len(f) < 13 {
		return 0
	}
	u, _ := strconv.ParseFloat(f[11], 64)
	k, _ := strconv.ParseFloat(f[12], 64)
	return u + k
}

func rssMB(pid int) float64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "VmRSS:"); ok {
			kb, _ := strconv.ParseFloat(strings.Fields(v)[0], 64)
			return kb / 1024
		}
	}
	return 0
}

func countLines(path, substr string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if strings.Contains(sc.Text(), substr) {
			n++
		}
	}
	return n
}

func clearDir(dir string) {
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		os.RemoveAll(dir + "/" + e.Name())
	}
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

func hostname() string { h, _ := os.Hostname(); return h }

func kernel() string {
	b, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return strings.TrimSpace(string(b))
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
