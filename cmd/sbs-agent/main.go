// Command sbs-agent is a Linux endpoint detection and response agent.
//
//	sbs-agent run   [-config agent.yaml] [-alerts file] [-events file]
//	sbs-agent scan  PATH...
//	sbs-agent rules [-config agent.yaml]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/avaadrian/sbs/assets"
	"github.com/avaadrian/sbs/internal/agent"
	"github.com/avaadrian/sbs/internal/rules"
	"github.com/avaadrian/sbs/internal/scanner"
)

var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("sbs-agent: ")
	cmd := "run"
	args := os.Args[1:]
	if len(args) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "run":
		err = run(args)
	case "scan":
		err = scan(args)
	case "rules":
		err = listRules(args)
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "usage: sbs-agent [run|scan|rules|version] [flags]\n")
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	fl := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fl.String("config", "", "config file (YAML)")
	alerts := fl.String("alerts", "", "alert output file (default stdout)")
	events := fl.String("events", "", "also write all telemetry to this file")
	source := fl.String("source", "", "process source: auto, netlink or procfs")
	ready := fl.String("ready-file", "", "create this file once collectors are running")
	fl.Parse(args)

	cfg, err := agent.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if *alerts != "" {
		cfg.AlertsPath = *alerts
	}
	if *events != "" {
		cfg.EventsPath = *events
	}
	if *source != "" {
		cfg.ProcessSource = *source
	}
	defRules, err := assets.Rules()
	if err != nil {
		return err
	}
	a, err := agent.New(cfg, defRules, assets.Signatures)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	start := time.Now()
	err = a.Run(ctx, func() {
		h, s := a.Signatures()
		log.Printf("running: source=%s rules=%d signatures=%d hashes=%d watches=%d",
			a.Source, a.Rules(), s, h, len(cfg.Watch))
		if *ready != "" {
			os.WriteFile(*ready, []byte(a.Source), 0o644)
		}
	})
	log.Printf("stopped after %s: events=%d scanned=%d alerts=%d", time.Since(start).Round(time.Second),
		a.Stats.Events.Load(), a.Stats.Scanned.Load(), a.Stats.Alerts.Load())
	return err
}

func scan(args []string) error {
	fl := flag.NewFlagSet("scan", flag.ExitOnError)
	sigs := fl.String("signatures", "", "extra signature file or directory")
	noDef := fl.Bool("no-defaults", false, "skip built-in signatures")
	fl.Parse(args)
	if fl.NArg() == 0 {
		return fmt.Errorf("usage: sbs-agent scan [-signatures path] PATH...")
	}
	s := scanner.New()
	if !*noDef {
		if err := assets.Signatures(s); err != nil {
			return err
		}
	}
	if *sigs != "" {
		if err := s.AddPath(*sigs); err != nil {
			return err
		}
	}
	enc := json.NewEncoder(os.Stdout)
	found, total := 0, 0
	for _, root := range fl.Args() {
		n, err := s.ScanTree(root, func(m scanner.Match) {
			found++
			enc.Encode(m)
		})
		total += n
		if err != nil {
			return err
		}
	}
	log.Printf("scanned %d files, %d detections", total, found)
	if found > 0 {
		os.Exit(1)
	}
	return nil
}

func listRules(args []string) error {
	fl := flag.NewFlagSet("rules", flag.ExitOnError)
	cfgPath := fl.String("config", "", "config file (YAML)")
	fl.Parse(args)
	cfg, err := agent.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	var all []*rules.Rule
	if !cfg.NoDefaults {
		if all, err = assets.Rules(); err != nil {
			return err
		}
	}
	for _, p := range cfg.RulePaths {
		rs, err := rules.LoadPath(p)
		if err != nil {
			return err
		}
		all = append(all, rs...)
	}
	if _, err := rules.NewEngine(all); err != nil {
		return err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	for _, r := range all {
		fmt.Printf("%-13s %-8s %-8s %-32s %s\n", r.ID, r.Event, r.Severity, strings.Join(r.MITRE, ","), r.Title)
	}
	return nil
}
