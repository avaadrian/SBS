// Command sbs-bench runs safe attack simulations against sbs-agent and reports
// detection rate, time to detect, false positives and resource cost.
//
// It must run as root on Linux (the agent's netlink collector needs it).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/avaadrian/sbs/internal/bench"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("sbs-bench: ")
	agent := flag.String("agent", "", "path to sbs-agent (default: next to this binary, then $PATH)")
	source := flag.String("source", "", "agent process source: auto, netlink or procfs")
	timeout := flag.Duration("timeout", 3*time.Second, "time to wait for each detection")
	load := flag.Int("load", 300, "short-lived processes in the exec-burst phase (0 to skip)")
	only := flag.String("only", "", "run only scenarios whose name contains this")
	jsonOut := flag.String("json", "", "write the JSON report here")
	mdOut := flag.String("md", "", "write a Markdown report here")
	minRate := flag.Float64("min-detection", 0, "exit 1 if the detection rate is below this (0..1)")
	maxFP := flag.Int("max-fp", -1, "exit 1 if there are more false positives than this (-1 = no limit)")
	keep := flag.Bool("keep", false, "keep the sandbox directory for inspection")
	heldout := flag.Bool("heldout", false, "run the independent held-out scenario set instead of the built-in one")
	flag.Parse()

	path, err := findAgent(*agent)
	if err != nil {
		log.Fatal(err)
	}
	rep, err := bench.Run(bench.Options{
		AgentPath: path, Source: *source, Timeout: *timeout, LoadExecs: *load, Heldout: *heldout,
		Only: *only, Keep: *keep, Log: os.Stdout,
	})
	if err != nil {
		log.Fatal(err)
	}
	rep.WriteText(os.Stdout)
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*jsonOut, append(b, '\n'), 0o644); err != nil {
			log.Fatal(err)
		}
	}
	if *mdOut != "" {
		f, err := os.Create(*mdOut)
		if err != nil {
			log.Fatal(err)
		}
		rep.WriteMarkdown(f)
		f.Close()
	}
	fail := false
	if rep.DetectionRate < *minRate {
		fmt.Printf("FAIL: detection rate %.2f below %.2f\n", rep.DetectionRate, *minRate)
		fail = true
	}
	if *maxFP >= 0 && len(rep.FalsePositives) > *maxFP {
		fmt.Printf("FAIL: %d false positives, limit %d\n", len(rep.FalsePositives), *maxFP)
		fail = true
	}
	if fail {
		os.Exit(1)
	}
}

func findAgent(p string) (string, error) {
	if p != "" {
		return p, nil
	}
	if self, err := os.Executable(); err == nil {
		c := filepath.Join(filepath.Dir(self), "sbs-agent")
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return exec.LookPath("sbs-agent")
}
