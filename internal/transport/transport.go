// Package transport uploads alerts and heartbeats to sbs-server. Alerts are
// batched, gzip-compressed and POSTed; when the server is unreachable or
// failing they are spooled to disk and resent on the next flush, so telemetry
// survives outages. Alert IDs make the resend idempotent.
package transport

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/avaadrian/sbs/internal/api"
	"github.com/avaadrian/sbs/internal/event"
)

// errRetry marks a failure worth retrying later (network error or 5xx). Other
// failures (4xx) are not retried: the request itself is bad.
var errRetry = errors.New("transport: retriable failure")

// maxServerBody caps a server response the agent will decode, so a malicious or
// buggy server cannot OOM the agent with an unbounded body.
const maxServerBody = 1 << 20 // 1 MiB: large enough for any heartbeat/ruleset, small enough that YAML parsing cannot overflow the stack

// Config configures a Client. Zero values take documented defaults.
type Config struct {
	ServerURL string   // base URL of sbs-server, e.g. https://sbs.example.com
	Token     string   // agent bearer token
	Host      api.Host // this host's identity, sent with every batch (fallback)
	// HostProvider, when set, supplies a fresh host snapshot for each upload so
	// the process source and current effective response mode are never stale.
	HostProvider func() api.Host
	SpoolDir     string // directory for spooled batches when offline

	BatchSize         int           // alerts per batch (default 100)
	FlushInterval     time.Duration // max time alerts wait before upload (default 5s)
	HeartbeatInterval time.Duration // caller's heartbeat cadence (default 30s)
	HTTPTimeout       time.Duration // per-request timeout (default 30s)
	MaxSpoolFiles     int           // cap on spooled batches (default 2000)
	// Insecure permits a plaintext http:// server URL to a non-loopback host.
	// Without it, only https or a loopback http endpoint is allowed, so the
	// bearer token and telemetry are not sent in cleartext over a network.
	Insecure bool
	// CAFile is an optional PEM bundle of certificate authorities used to verify
	// the server's TLS certificate. When set it replaces the system trust store,
	// so a server with a private/self-signed CA can be trusted without Insecure.
	CAFile string
}

// Client uploads alerts and heartbeats. It is safe for concurrent use.
type Client struct {
	cfg  Config
	http *http.Client
	in   chan *event.Alert

	mu sync.Mutex // guards spool-directory operations
}

// New validates cfg, applies defaults and creates the spool directory.
func New(cfg Config) (*Client, error) {
	if cfg.ServerURL == "" {
		return nil, errors.New("transport: ServerURL is required")
	}
	if cfg.SpoolDir == "" {
		return nil, errors.New("transport: SpoolDir is required")
	}
	cfg.ServerURL = strings.TrimRight(cfg.ServerURL, "/")
	if err := checkURL(cfg.ServerURL, cfg.Insecure); err != nil {
		return nil, err
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 30 * time.Second
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 30 * time.Second
	}
	if cfg.MaxSpoolFiles <= 0 {
		cfg.MaxSpoolFiles = 2000
	}
	if err := os.MkdirAll(cfg.SpoolDir, 0o700); err != nil {
		return nil, err
	}
	hc := &http.Client{Timeout: cfg.HTTPTimeout}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("transport: read ca file %s: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("transport: no certificates found in ca file %s", cfg.CAFile)
		}
		// Clone the default transport so proxy and timeout settings are kept.
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		hc.Transport = tr
	}
	bufN := cfg.BatchSize * 8
	if bufN < 256 {
		bufN = 256
	}
	return &Client{
		cfg:  cfg,
		http: hc,
		in:   make(chan *event.Alert, bufN),
	}, nil
}

// checkURL rejects a plaintext http:// server URL to a non-loopback host unless
// insecure is set, so the bearer token is not sent in cleartext over a network.
func checkURL(raw string, insecure bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("transport: invalid server url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("transport: server url must be http or https, got %q", u.Scheme)
	}
	if u.Scheme == "http" && !insecure {
		host := u.Hostname()
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("transport: refusing plaintext http to non-loopback host %q (use https or set insecure)", host)
		}
	}
	return nil
}

// Enqueue buffers an alert for upload. It never blocks: if the buffer is full
// the alert is spooled straight to disk so nothing is lost.
func (c *Client) Enqueue(a *event.Alert) {
	if a == nil {
		return
	}
	select {
	case c.in <- a:
	default:
		c.spool([]*event.Alert{a})
	}
}

// Run batches enqueued alerts and flushes them on FlushInterval or when a batch
// fills, resending spooled batches first. It returns when ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	t := time.NewTicker(c.cfg.FlushInterval)
	defer t.Stop()
	batch := make([]*event.Alert, 0, c.cfg.BatchSize)
	for {
		select {
		case <-ctx.Done():
			// Drain whatever is still buffered so a burst just before shutdown
			// is flushed (or spooled), never silently dropped.
		drain:
			for {
				select {
				case a := <-c.in:
					batch = append(batch, a)
				default:
					break drain
				}
			}
			if len(batch) > 0 {
				fctx, cancel := context.WithTimeout(context.Background(), c.cfg.HTTPTimeout)
				c.flush(fctx, batch)
				cancel()
			}
			return nil
		case a := <-c.in:
			batch = append(batch, a)
			if len(batch) >= c.cfg.BatchSize {
				c.flush(ctx, batch)
				batch = batch[:0]
			}
		case <-t.C:
			c.flush(ctx, batch)
			batch = batch[:0]
		}
	}
}

// flush resends spooled batches, then uploads batch; on a retriable failure the
// batch is spooled for next time.
func (c *Client) flush(ctx context.Context, batch []*event.Alert) {
	c.resendSpool(ctx)
	if len(batch) == 0 {
		return
	}
	body, err := c.marshalBatch(batch)
	if err != nil {
		return // unencodable: drop
	}
	if err := c.postAlerts(ctx, body); err != nil {
		if errors.Is(err, errRetry) {
			c.spoolBytes(body)
		}
	}
}

// marshalBatch encodes batch as a wire AlertBatch.
func (c *Client) marshalBatch(batch []*event.Alert) ([]byte, error) {
	host := c.cfg.Host
	if c.cfg.HostProvider != nil {
		host = c.cfg.HostProvider()
	}
	return json.Marshal(api.AlertBatch{Host: host, Alerts: batch})
}

// postAlerts gzip-compresses and POSTs a JSON AlertBatch body.
func (c *Client) postAlerts(ctx context.Context, jsonBody []byte) error {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(jsonBody); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.ServerURL+api.PathAlerts, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", errRetry, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 500,
		resp.StatusCode == http.StatusRequestTimeout,  // 408
		resp.StatusCode == http.StatusTooManyRequests, // 429
		resp.StatusCode == http.StatusTooEarly:        // 425
		// Transient: retry/keep spooled rather than dropping telemetry.
		return fmt.Errorf("%w: status %d", errRetry, resp.StatusCode)
	default:
		return fmt.Errorf("transport: status %d", resp.StatusCode)
	}
}

// Heartbeat POSTs a heartbeat and returns the server's pending commands.
func (c *Client) Heartbeat(ctx context.Context, hb api.Heartbeat) (*api.HeartbeatResponse, error) {
	body, err := json.Marshal(hb)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.ServerURL+api.PathHeartbeat, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("transport: heartbeat status %d", resp.StatusCode)
	}
	var out api.HeartbeatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxServerBody)).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// FetchRules GETs the server's current custom rule set. The agent calls it when
// a heartbeat reports a rules version it does not have loaded.
func (c *Client) FetchRules(ctx context.Context) (api.RuleSet, error) {
	var out api.RuleSet
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.ServerURL+api.PathRules, nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	resp, err := c.http.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, resp.Body)
		return out, fmt.Errorf("transport: rules status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxServerBody)).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

// CommandResult POSTs the outcome of a server-issued command.
func (c *Client) CommandResult(ctx context.Context, r api.CommandResult) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.ServerURL+api.PathCommandResult, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("transport: command result status %d", resp.StatusCode)
	}
	return nil
}

// Backlog is the number of batches currently spooled to disk.
func (c *Client) Backlog() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.spoolFilesLocked())
}

// spool marshals a batch and writes it to disk.
func (c *Client) spool(batch []*event.Alert) {
	body, err := c.marshalBatch(batch)
	if err != nil {
		return
	}
	c.spoolBytes(body)
}

// spoolBytes writes an already-encoded batch to the spool directory, dropping
// the oldest batches first when the cap is reached. The filename is timestamp
// ordered so the oldest sorts first.
func (c *Client) spoolBytes(body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	names := c.spoolFilesLocked()
	for len(names) >= c.cfg.MaxSpoolFiles {
		os.Remove(filepath.Join(c.cfg.SpoolDir, names[0]))
		names = names[1:]
	}
	name := fmt.Sprintf("%020d-%s.json", time.Now().UnixNano(), randHex())
	tmp := filepath.Join(c.cfg.SpoolDir, "."+name+".tmp")
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return
	}
	os.Rename(tmp, filepath.Join(c.cfg.SpoolDir, name))
}

// resendSpool uploads spooled batches oldest-first, deleting each only after a
// 2xx. It stops at the first retriable failure, leaving the rest for later.
func (c *Client) resendSpool(ctx context.Context) {
	c.mu.Lock()
	names := c.spoolFilesLocked()
	c.mu.Unlock()
	for _, n := range names {
		p := filepath.Join(c.cfg.SpoolDir, n)
		body, err := os.ReadFile(p)
		if err != nil {
			continue // removed concurrently, or unreadable
		}
		err = c.postAlerts(ctx, body)
		switch {
		case err == nil:
			c.removeSpool(p)
		case errors.Is(err, errRetry):
			return // server still down: keep the rest spooled
		default:
			c.removeSpool(p) // non-retriable: the batch is bad, drop it
		}
	}
}

func (c *Client) removeSpool(path string) {
	c.mu.Lock()
	os.Remove(path)
	c.mu.Unlock()
}

// spoolFilesLocked lists spool batches oldest-first. Call with c.mu held.
func (c *Client) spoolFilesLocked() []string {
	entries, err := os.ReadDir(c.cfg.SpoolDir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".json") {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names) // zero-padded nanosecond prefix => oldest first
	return names
}

func randHex() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
