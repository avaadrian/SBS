package transport

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avaadrian/sbs/internal/api"
	"github.com/avaadrian/sbs/internal/event"
)

// decodeBatch reads a gzip-compressed AlertBatch request body.
func decodeBatch(t *testing.T, r *http.Request) api.AlertBatch {
	t.Helper()
	if r.Header.Get("Content-Encoding") != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", r.Header.Get("Content-Encoding"))
	}
	gz, err := gzip.NewReader(r.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	var ab api.AlertBatch
	if err := json.NewDecoder(gz).Decode(&ab); err != nil {
		t.Fatalf("decode batch: %v", err)
	}
	return ab
}

func waitFor(cond func() bool, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

func TestAlertsUploadGzip(t *testing.T) {
	got := make(chan api.AlertBatch, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != api.PathAlerts {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer secret" {
			t.Errorf("Authorization = %q", auth)
		}
		ab := decodeBatch(t, r)
		got <- ab
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c, err := New(Config{
		ServerURL:     srv.URL,
		Token:         "secret",
		Host:          api.Host{ID: "host-1"},
		SpoolDir:      t.TempDir(),
		BatchSize:     2,
		FlushInterval: 20 * time.Millisecond,
		HTTPTimeout:   time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	c.Enqueue(&event.Alert{ID: "a1", RuleID: "SBS-TEST-1"})
	c.Enqueue(&event.Alert{ID: "a2", RuleID: "SBS-TEST-2"})

	select {
	case ab := <-got:
		if len(ab.Alerts) != 2 {
			t.Fatalf("got %d alerts, want 2", len(ab.Alerts))
		}
		if ab.Host.ID != "host-1" {
			t.Fatalf("host ID = %q", ab.Host.ID)
		}
		if ab.Alerts[0].ID != "a1" {
			t.Fatalf("alert ID = %q", ab.Alerts[0].ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for alert batch")
	}
	if c.Backlog() != 0 {
		t.Fatalf("backlog = %d, want 0", c.Backlog())
	}
}

func TestSpoolOn503AndResend(t *testing.T) {
	var down atomic.Bool
	down.Store(true)
	var accepted atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		ab := decodeBatch(t, r)
		accepted.Add(int32(len(ab.Alerts)))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c, err := New(Config{
		ServerURL:     srv.URL,
		Token:         "secret",
		SpoolDir:      t.TempDir(),
		BatchSize:     50,
		FlushInterval: 15 * time.Millisecond,
		HTTPTimeout:   time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	c.Enqueue(&event.Alert{ID: "spill-1", RuleID: "SBS-TEST-1"})

	// While the server is down, the batch must land in the spool.
	if !waitFor(func() bool { return c.Backlog() >= 1 }, 2*time.Second) {
		t.Fatal("expected a spool file after a 503")
	}
	if accepted.Load() != 0 {
		t.Fatalf("server accepted %d alerts while down", accepted.Load())
	}

	// Server recovers: the next flush resends the spool and clears it.
	down.Store(false)
	if !waitFor(func() bool { return c.Backlog() == 0 && accepted.Load() >= 1 }, 2*time.Second) {
		t.Fatalf("expected resend after recovery: backlog=%d accepted=%d", c.Backlog(), accepted.Load())
	}
}

func TestHeartbeatAndCommandResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case api.PathHeartbeat:
			json.NewEncoder(w).Encode(api.HeartbeatResponse{
				ServerTime: time.Now().UTC(),
				Commands:   []api.Command{{ID: "c1", Type: api.CmdKill, PID: 1234}},
			})
		case api.PathCommandResult:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "wrong path", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c, err := New(Config{ServerURL: srv.URL, Token: "secret", SpoolDir: t.TempDir(), HTTPTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Heartbeat(context.Background(), api.Heartbeat{Host: api.Host{ID: "host-1"}})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if len(resp.Commands) != 1 || resp.Commands[0].Type != api.CmdKill {
		t.Fatalf("commands = %+v", resp.Commands)
	}
	if err := c.CommandResult(context.Background(), api.CommandResult{CommandID: "c1", OK: true}); err != nil {
		t.Fatalf("command result: %v", err)
	}
}
