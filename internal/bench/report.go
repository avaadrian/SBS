package bench

import (
	"fmt"
	"io"
	"strings"
)

// suiteName labels the scenario set, defaulting older reports to "builtin".
func suiteName(s string) string {
	if s == "" {
		return "builtin"
	}
	return s
}

// WriteText prints a human-readable summary.
func (r *Report) WriteText(w io.Writer) {
	fmt.Fprintf(w, "\nSBS benchmark [%s]  %s  kernel %s  source %s\n", suiteName(r.Suite), r.Time.Format("2006-01-02 15:04:05Z"), r.Kernel, r.Source)
	fmt.Fprintf(w, "  detection rate   %d/%d (%.0f%%)\n", r.Detected, r.Total, 100*r.DetectionRate)
	fmt.Fprintf(w, "  median latency   %.0f ms\n", r.MedianLatencyMS)
	fmt.Fprintf(w, "  false positives  %d over %d benign commands\n", len(r.FalsePositives), r.BenignCommands)
	for _, fp := range r.FalsePositives {
		fmt.Fprintf(w, "    - %s\n", fp)
	}
	if r.LoadExecs > 0 {
		fmt.Fprintf(w, "  exec visibility  %d/%d short-lived processes (%.1f%%) in %.1fs\n", r.LoadSeen, r.LoadExecs, 100*r.LoadVisibility, r.LoadDuration)
	}
	fmt.Fprintf(w, "  agent cpu        avg %.1f%%  peak %.1f%%\n", r.CPUAvgPct, r.CPUPeakPct)
	fmt.Fprintf(w, "  agent memory     peak RSS %.1f MB\n", r.RSSPeakMB)
	fmt.Fprintf(w, "  agent counters   events=%d scanned=%d\n", r.AgentEvents, r.AgentScanned)
}

// WriteMarkdown writes the report as a Markdown table.
func (r *Report) WriteMarkdown(w io.Writer) {
	fmt.Fprintf(w, "# SBS benchmark report\n\n")
	fmt.Fprintf(w, "%s · suite `%s` · kernel `%s` · process source `%s`\n\n", r.Time.Format("2006-01-02 15:04 UTC"), suiteName(r.Suite), r.Kernel, r.Source)
	fmt.Fprintf(w, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(w, "| Detection rate | %d/%d (%.0f%%) |\n", r.Detected, r.Total, 100*r.DetectionRate)
	fmt.Fprintf(w, "| Median time to detect | %.0f ms |\n", r.MedianLatencyMS)
	fmt.Fprintf(w, "| False positives | %d over %d benign commands |\n", len(r.FalsePositives), r.BenignCommands)
	if r.LoadExecs > 0 {
		fmt.Fprintf(w, "| Exec visibility (short-lived) | %d/%d (%.1f%%) |\n", r.LoadSeen, r.LoadExecs, 100*r.LoadVisibility)
	}
	fmt.Fprintf(w, "| Agent CPU (avg / peak) | %.1f%% / %.1f%% |\n", r.CPUAvgPct, r.CPUPeakPct)
	fmt.Fprintf(w, "| Agent peak RSS | %.1f MB |\n\n", r.RSSPeakMB)
	fmt.Fprintf(w, "| Scenario | ATT&CK | Tactic | Result | Latency | Alerts raised |\n|---|---|---|---|---|---|\n")
	for _, s := range r.Scenarios {
		res, lat := "❌ missed", "–"
		if s.Detected {
			res, lat = "✅ "+s.Matched, fmt.Sprintf("%.0f ms", s.LatencyMS)
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s |\n", s.Name, s.Technique, s.Tactic, res, lat, strings.Join(s.Alerts, ", "))
	}
	if len(r.FalsePositives) > 0 {
		fmt.Fprintf(w, "\n## False positives\n\n")
		for _, fp := range r.FalsePositives {
			fmt.Fprintf(w, "- `%s`\n", fp)
		}
	}
}
