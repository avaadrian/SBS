// Command sbs-server is the central collector and web console for sbs agents.
// Agents POST alerts and heartbeats (bearer-token authenticated); operators use
// the dashboard and JSON API bound to localhost.
//
//	sbs-server [-addr 127.0.0.1:8080] [-db sbs.db] [-token TOKEN]
//	           [-llm off|ollama|anthropic] [-auto-triage high]
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/avaadrian/sbs/internal/llm"
	"github.com/avaadrian/sbs/internal/server"
	"github.com/avaadrian/sbs/internal/store"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("sbs-server: ")
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address (bind localhost for the console)")
	dbPath := flag.String("db", "sbs.db", "SQLite database path (\":memory:\" for ephemeral)")
	token := flag.String("token", "", "agent bearer token (or SBS_AGENT_TOKEN)")
	llmMode := flag.String("llm", "off", "AI analyst: off|ollama|anthropic")
	llmModel := flag.String("llm-model", "", "model id (default: provider's default)")
	llmURL := flag.String("llm-url", "", "Ollama server URL (default http://localhost:11434) or Anthropic base URL")
	autoTriage := flag.String("auto-triage", "high", "auto-triage alerts at or above this severity (info|low|medium|high|critical; empty to disable)")
	flag.Parse()

	if *token == "" {
		*token = os.Getenv("SBS_AGENT_TOKEN")
	}
	if *token == "" {
		log.Print("warning: no agent token set (-token or SBS_AGENT_TOKEN); agent authentication is effectively disabled")
	}

	analyst, err := llm.New(llm.Config{Provider: *llmMode, Model: *llmModel, BaseURL: *llmURL})
	if err != nil {
		return err
	}
	if analyst != nil {
		log.Printf("AI analyst: %s", analyst.Name())
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	srv := server.New(st, server.Config{
		AgentToken:            *token,
		Analyst:               analyst,
		AutoTriageMinSeverity: *autoTriage,
	})

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() {
		log.Printf("listening on %s (db=%s, llm=%s, auto-triage=%q)", *addr, *dbPath, *llmMode, *autoTriage)
		errc <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		log.Print("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutCtx); err != nil {
			return err
		}
		srv.Wait() // let in-flight background triage finish
		return nil
	}
}
