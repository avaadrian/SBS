// Command sbs-server is the central collector and web console for sbs agents.
// Agents POST alerts and heartbeats (bearer-token authenticated); operators use
// the dashboard and JSON API bound to localhost.
//
//	sbs-server [-addr 127.0.0.1:8080] [-db sbs.db] [-token TOKEN]
//	           [-console-token TOKEN] [-tls-cert FILE -tls-key FILE]
//	           [-llm off|ollama|anthropic] [-auto-triage high]
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net"
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
	consoleToken := flag.String("console-token", "", "console operator token (or SBS_CONSOLE_TOKEN); empty leaves the console open")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (serves HTTPS with -tls-key)")
	tlsKey := flag.String("tls-key", "", "TLS private key file (serves HTTPS with -tls-cert)")
	insecure := flag.Bool("insecure-no-auth", false, "allow running with no agent/console token (open endpoints — testing only)")
	flag.Parse()

	if *token == "" {
		*token = os.Getenv("SBS_AGENT_TOKEN")
	}
	if *token == "" && !*insecure {
		return errors.New("no agent token set: pass -token or SBS_AGENT_TOKEN, or -insecure-no-auth to run without authentication")
	}
	if *token == "" {
		log.Print("warning: -insecure-no-auth set; agent endpoints are unauthenticated")
	}

	if *consoleToken == "" {
		*consoleToken = os.Getenv("SBS_CONSOLE_TOKEN")
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		return errors.New("-tls-cert and -tls-key must be given together")
	}
	servingTLS := *tlsCert != "" && *tlsKey != ""
	// A non-loopback bind with an open console would expose the console to the
	// network; refuse unless the operator explicitly opts out.
	if !isLoopbackAddr(*addr) && *consoleToken == "" && !*insecure {
		return errors.New("refusing to bind a non-loopback address with no console token: pass -console-token/SBS_CONSOLE_TOKEN, or -insecure-no-auth to allow an open console")
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
		ConsoleToken:          *consoleToken,
		TLS:                   servingTLS,
		Analyst:               analyst,
		AutoTriageMinSeverity: *autoTriage,
	})

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if servingTLS {
		httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() {
		scheme := "http"
		if servingTLS {
			scheme = "https"
		}
		log.Printf("listening on %s://%s (db=%s, llm=%s, auto-triage=%q)", scheme, *addr, *dbPath, *llmMode, *autoTriage)
		if servingTLS {
			errc <- httpSrv.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			errc <- httpSrv.ListenAndServe()
		}
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

// isLoopbackAddr reports whether a listen address binds only the loopback
// interface. An empty host (e.g. ":8080", all interfaces) is not loopback.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
