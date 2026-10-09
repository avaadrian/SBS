# Deploying SBS

Two pieces ship separately:

- **`sbs-server`** — central collector + web console. Runs fine in a container or as a
  hardened systemd service. Unprivileged.
- **`sbs-agent`** — the host EDR. Belongs on the host, as a systemd service with a small,
  specific capability set. It *can* run in a container, but only a privileged, namespace-
  sharing one — see [Running the agent in a container](#running-the-agent-in-a-container).

All commands below are run from the repo root unless noted.

---

## Quick start with Docker Compose

Brings up `sbs-server` (console on `127.0.0.1:8080`, SQLite in a named volume) and a local
`ollama` for AI triage.

```sh
# 1. Generate strong tokens into .env (never commit it).
./scripts/gen-tokens.sh --write          # creates ./.env (mode 600) from .env.example
#   or: cp .env.example .env && openssl rand -hex 32   # and paste the value(s)

# 2. Build and start.
docker compose up -d --build
#   same as: make compose-up

# 3. One-time: pull the triage model into the ollama volume.
docker compose exec ollama ollama pull llama3.1

# 4. Open the console.
#   http://127.0.0.1:8080
```

Flow summary: **`gen-tokens.sh --write` → `docker compose up -d --build` → `ollama pull llama3.1` → browse `127.0.0.1:8080`.**

Stop with `docker compose down` (add `-v` to also drop the DB and model volumes).

What the compose file wires up:

- `sbs-server` reads `SBS_AGENT_TOKEN` from the environment and runs
  `-addr 0.0.0.0:8080 -db /data/sbs.db -llm ollama -llm-url http://ollama:11434 -auto-triage high`.
  `/data` is a named volume, so the SQLite DB survives restarts.
- The port is published on `127.0.0.1` only. The console in the current build is
  unauthenticated, so do **not** bind it to `0.0.0.0` without putting auth/TLS in front
  (below).
- `ollama` has no model until you `ollama pull`. Until then, triage calls return an error
  and alerts are simply stored untriaged.

### Switching to the Claude API instead of Ollama

Set `ANTHROPIC_API_KEY` in `.env` and change the server `command:` in `docker-compose.yml`
to `-llm anthropic` (drop the `-llm-url` line). The server uses `claude-opus-5-5` by
default; override with `-llm-model`.

---

## Tokens

Nothing is hardcoded. Generate 256-bit hex tokens and keep them out of version control:

```sh
./scripts/gen-tokens.sh            # prints SBS_AGENT_TOKEN / SBS_CONSOLE_TOKEN
./scripts/gen-tokens.sh --write    # writes them into ./.env (mode 600)
openssl rand -hex 32               # a single token, by hand
```

- **`SBS_AGENT_TOKEN`** — required. Agents send it as a bearer token; the server compares
  it in constant time. The **same** value must be set as `server.token` in each agent's
  `/etc/sbs/agent.yaml`.
- **`SBS_CONSOLE_TOKEN`** — operator/console login token. It is consumed by the
  console-auth build described in [`docs/CONSOLE_API.md`](../docs/CONSOLE_API.md). It is
  passed through compose and the systemd env file so it is ready when that build is in
  use; the current server binary authenticates **agents** (via `SBS_AGENT_TOKEN`) and
  serves the console openly, so keep the console on localhost or behind a proxy until
  console auth is enabled.

---

## Enabling console auth and TLS

The current `sbs-server` CLI exposes: `-addr`, `-db`, `-token`, `-llm`, `-llm-model`,
`-llm-url`, `-auto-triage`, `-insecure-no-auth`. The console API spec
([`docs/CONSOLE_API.md`](../docs/CONSOLE_API.md)) defines the operator-auth and TLS
surface that builds toward it:

- `-console-token <T>` / `SBS_CONSOLE_TOKEN` — operator login.
- `-tls-cert <file> -tls-key <file>` — serve HTTPS directly; agents trust it via
  `server.ca_file` in `agent.yaml`.

Until those flags exist in your `sbs-server` build, do not add them to the command line
(the binary rejects unknown flags). Two ways to get auth + TLS today:

1. **Reverse proxy (recommended now).** Terminate TLS and require auth at a proxy (Caddy,
   nginx, an identity-aware proxy) in front of `127.0.0.1:8080`. Example Caddyfile:

   ```
   sbs.example.com {
       reverse_proxy 127.0.0.1:8080
       # basicauth / forward_auth / mTLS as you prefer
   }
   ```

2. **Native (when supported).** Put the cert/key on the server, add
   `-tls-cert /etc/sbs/tls/cert.pem -tls-key /etc/sbs/tls/key.pem` and
   `-console-token "$SBS_CONSOLE_TOKEN"` to `ExecStart`, and set `server.url: https://…`
   plus `server.ca_file` on the agents.

---

## Server as a systemd service (native, no Docker)

```sh
make build
sudo install -D -m 0755 bin/sbs-server /usr/local/bin/sbs-server
sudo useradd --system --home-dir /var/lib/sbs-server --shell /usr/sbin/nologin sbs-server
sudo install -D -m 0600 deploy/server.env.example /etc/sbs/server.env
sudo ./scripts/gen-tokens.sh | sudo tee -a /etc/sbs/server.env >/dev/null   # append tokens
sudo "$EDITOR" /etc/sbs/server.env                                          # review; remove blank dupes
sudo install -m 0644 deploy/sbs-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sbs-server
systemctl status sbs-server
```

`deploy/sbs-server.service` runs as the unprivileged `sbs-server` user, keeps the DB under
`/var/lib/sbs-server` (a systemd `StateDirectory`, the only `ReadWritePaths`), and applies
`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, kernel/`/proc` protections,
`MemoryDenyWriteExecute`, a `@system-service` syscall filter, and an empty capability set.
If the service fails to start, relax `MemoryDenyWriteExecute` / `SystemCallFilter` first
(some toolchains trip them) — see the comments in the unit.

---

## Installing an agent on a host

Use the installer with a prebuilt binary (from `make build` or a `make release` tarball):

```sh
make build                              # produces bin/sbs-agent
sudo ./scripts/install-agent.sh         # discovers bin/sbs-agent automatically
#   or: sudo ./scripts/install-agent.sh --bin /path/to/sbs-agent
```

It copies `sbs-agent` to `/usr/local/bin`, installs `configs/agent.yaml` to
`/etc/sbs/agent.yaml` **only if absent** (otherwise it drops `agent.yaml.dist` beside it),
creates `/var/lib/sbs` (+ `quarantine`, `spool`) and `/var/log/sbs`, and installs + enables
`deploy/sbs-agent.service`. It does not start the agent — edit the config first:

```yaml
# /etc/sbs/agent.yaml — point it at the server to upload alerts
server:
  url: https://sbs.example.com         # or http://SERVER_IP:8080 on a trusted LAN
  token: <SBS_AGENT_TOKEN>             # must match the server's token
  spool_dir: /var/lib/sbs/spool
# remote_commands: false               # leave off unless you want console-driven kill/quarantine
```

Then:

```sh
sudo systemctl start sbs-agent
journalctl -u sbs-agent -f
```

Remove it with `sudo ./scripts/uninstall-agent.sh` (add `--purge` to also delete config,
state and logs).

The agent unit grants exactly `CAP_NET_ADMIN` (netlink process connector),
`CAP_SYS_PTRACE` + `CAP_DAC_READ_SEARCH` + `CAP_DAC_OVERRIDE` (read every process's
`/proc` and sensitive files) and `CAP_KILL` (terminate a malicious process regardless of
its owner), with `NoNewPrivileges=yes` and `ProtectHome=read-only`. It runs as root
because those collectors require it.

---

## Running the agent in a container

**This is a documented convenience, not an isolation boundary.** The agent is the host's
EDR; to do its job in a container it must see the host's processes and kernel events, so
you hand it most of what a container normally hides:

- `--pid=host` — so it enriches real host PIDs from `/proc`.
- `--network=host` **or** `--cap-add=NET_ADMIN` — the netlink process connector is a
  `NETLINK_CONNECTOR` socket that needs `CAP_NET_ADMIN` and the host net namespace to see
  host `exec` events.
- `--cap-add=SYS_PTRACE --cap-add=DAC_READ_SEARCH` — read other users' `/proc` and
  sensitive paths.
- `--cap-add=KILL` — so response actions can terminate processes owned by any user.
- Writable host paths for state (`/var/lib/sbs`) and the alert log (`/var/log/sbs`).

A container with `--pid=host` + these capabilities can trivially affect the whole host.
You gain almost no isolation over the native systemd service and add moving parts, so
**prefer `scripts/install-agent.sh` on real hosts.** Use the container only for labs or
immutable-OS hosts where a package install is not an option.

Build and run:

```sh
make docker-agent        # builds the sbs-agent image (also: make docker for both)

sudo docker run -d --name sbs-agent \
  --restart unless-stopped \
  --pid=host \
  --network=host \
  --cap-add=NET_ADMIN --cap-add=SYS_PTRACE --cap-add=DAC_READ_SEARCH --cap-add=KILL \
  --security-opt apparmor=unconfined \
  -v /etc/sbs/agent.yaml:/etc/sbs/agent.yaml:ro \
  -v /var/lib/sbs:/var/lib/sbs \
  -v /var/log/sbs:/var/log/sbs \
  sbs-agent:latest run -config /etc/sbs/agent.yaml
```

The equivalent is pre-written and commented out as the `sbs-agent` service in
`docker-compose.yml`. Quarantine moves files into `quarantine_dir` (default
`/var/lib/sbs/quarantine`); keep that on a writable host mount so quarantined files
persist and are reachable from the host.

---

## Images and the release build

- `make docker` builds `sbs-server` and `sbs-agent` images from the single multi-stage
  `Dockerfile` (`--target sbs-server` / `--target sbs-agent`). Both binaries are
  `CGO_ENABLED=0` static builds on `alpine:3.22.6`; the Go toolchain is pinned to
  `golang:1.24.7-alpine3.22`, Ollama to `ollama/ollama:0.40.2`.
- `make release` cross-compiles static `linux/amd64` and `linux/arm64` binaries
  (`-trimpath`, version-stamped) for all three commands into `dist/`, one tarball per
  arch (`dist/sbs-<version>-linux-<arch>.tar.gz`). `install-agent.sh` can install straight
  from an unpacked release tree.
