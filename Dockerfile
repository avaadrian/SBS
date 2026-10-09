# syntax=docker/dockerfile:1.9
#
# Multi-stage build for the SBS EDR stack. Two runtime targets share one builder:
#
#   docker build --target sbs-server -t sbs-server .   # central collector + web console
#   docker build --target sbs-agent  -t sbs-agent  .   # host agent (PRIVILEGED — see deploy/README.md)
#
# Both binaries are built CGO_ENABLED=0 (pure-Go SQLite via modernc.org/sqlite), so the
# runtime images carry a single static binary on a minimal Alpine base.

# ---------------------------------------------------------------------------
# Builder: pinned Go toolchain, builds the static binaries.
# ---------------------------------------------------------------------------
FROM golang:1.24.7-alpine3.22 AS builder

WORKDIR /src

# Download modules first so the cache survives source-only changes.
COPY go.mod go.sum ./
RUN go mod download

# Build metadata (matches the Makefile's -X main.version).
ARG VERSION=docker
# Cross-compile targets are honoured when set by buildx; default to the build host.
ARG TARGETOS=linux
ARG TARGETARCH=amd64

COPY . .

RUN set -eux; \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
      go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/sbs-server ./cmd/sbs-server; \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
      go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/sbs-agent ./cmd/sbs-agent

# ---------------------------------------------------------------------------
# sbs-agent runtime.
#
# The agent is NOT a well-isolated container: it needs the host PID namespace,
# host networking (or CAP_NET_ADMIN + CAP_SYS_PTRACE) for the netlink process
# connector, and read access to the host's /proc and sensitive paths. Running it
# in Docker trades isolation for convenience — see deploy/README.md for the full
# `docker run` invocation and the security tradeoffs. It runs as root by design.
# ---------------------------------------------------------------------------
FROM alpine:3.22.6 AS sbs-agent

RUN apk add --no-cache ca-certificates

COPY --from=builder /out/sbs-agent /usr/local/bin/sbs-agent
# Ship the example config as a default; mount your own over /etc/sbs/agent.yaml.
COPY configs/agent.yaml /etc/sbs/agent.yaml

# State (anomaly memory, quarantine) and logs. Bind-mount host paths over these
# in production so quarantined files and alerts survive the container.
VOLUME ["/var/lib/sbs", "/var/log/sbs"]

ENTRYPOINT ["sbs-agent"]
CMD ["run", "-config", "/etc/sbs/agent.yaml"]

# ---------------------------------------------------------------------------
# sbs-server runtime (default target).
#
# Runs unprivileged as uid 'sbs', persists the SQLite DB in /data, serves the
# console/API on :8080. Authenticates agents with SBS_AGENT_TOKEN.
# ---------------------------------------------------------------------------
FROM alpine:3.22.6 AS sbs-server

# ca-certificates: needed for `-llm anthropic` (Claude API over TLS).
# wget (busybox) powers the container HEALTHCHECK.
RUN apk add --no-cache ca-certificates \
 && addgroup -S sbs \
 && adduser -S -G sbs -h /data -s /sbin/nologin sbs \
 && mkdir -p /data \
 && chown sbs:sbs /data

COPY --from=builder /out/sbs-server /usr/local/bin/sbs-server

USER sbs
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080

# /api/overview needs no auth and always answers once the server is up.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/api/overview || exit 1

# SBS_AGENT_TOKEN is read from the environment by the server (see cmd/sbs-server).
# Override the CMD to add `-llm ollama -llm-url http://ollama:11434` etc.
ENTRYPOINT ["sbs-server"]
CMD ["-addr", "0.0.0.0:8080", "-db", "/data/sbs.db", "-auto-triage", "high"]
