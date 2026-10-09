#!/usr/bin/env bash
#
# install-agent.sh — install the sbs-agent host agent as a systemd service.
#
# Idempotent. Must run as root. Copies a prebuilt binary to /usr/local/bin,
# installs the config to /etc/sbs/agent.yaml (never overwriting an existing one),
# creates state/log dirs, and installs + enables the systemd unit.
#
#   sudo ./scripts/install-agent.sh                 # discover binary under ./ , ./bin , ./dist
#   sudo ./scripts/install-agent.sh --bin /path/to/sbs-agent
#   sudo ./scripts/install-agent.sh --start         # also start the service now
#
# It does NOT start the service by default: edit /etc/sbs/agent.yaml first
# (set server.url / server.token) then `systemctl start sbs-agent`.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)

PREFIX=/usr/local/bin
CONFIG_DIR=/etc/sbs
STATE_DIR=/var/lib/sbs
LOG_DIR=/var/log/sbs
UNIT_DIR=/etc/systemd/system
UNIT_NAME=sbs-agent.service

BIN_SRC=""
START=0

die() { echo "install-agent.sh: $*" >&2; exit 1; }
info() { echo "install-agent.sh: $*"; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --bin)   shift; [ "$#" -gt 0 ] || die "--bin needs a path"; BIN_SRC="$1" ;;
    --bin=*) BIN_SRC="${1#--bin=}" ;;
    --start) START=1 ;;
    -h|--help)
      sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo $0)"

# --- Locate the prebuilt binary ---------------------------------------------
# Map `uname -m` to the Go arch name used in dist/ (sbs-<ver>-linux-<arch>/).
case "$(uname -m)" in
  x86_64|amd64)        GOARCH=amd64 ;;
  aarch64|arm64)       GOARCH=arm64 ;;
  *)                   GOARCH="" ;;
esac

if [ -z "$BIN_SRC" ]; then
  for cand in \
    "${REPO_ROOT}/bin/sbs-agent" \
    "${REPO_ROOT}/sbs-agent" \
    "${SCRIPT_DIR}/sbs-agent"; do
    if [ -x "$cand" ]; then BIN_SRC="$cand"; break; fi
  done
fi
# Fall back to a release tree: dist/sbs-*-linux-<arch>/sbs-agent (newest match).
if [ -z "$BIN_SRC" ] && [ -n "$GOARCH" ]; then
  for cand in "${REPO_ROOT}"/dist/sbs-*-linux-"${GOARCH}"/sbs-agent; do
    if [ -x "$cand" ]; then BIN_SRC="$cand"; fi   # keep last (lexically newest)
  done
fi
[ -n "$BIN_SRC" ] || die "could not find a prebuilt sbs-agent binary; build it (make build) or pass --bin PATH"
[ -f "$BIN_SRC" ] || die "binary not found: $BIN_SRC"

# --- Locate the config and unit source --------------------------------------
CONFIG_SRC="${REPO_ROOT}/configs/agent.yaml"
UNIT_SRC="${REPO_ROOT}/deploy/${UNIT_NAME}"
[ -f "$CONFIG_SRC" ] || die "config not found: $CONFIG_SRC"
[ -f "$UNIT_SRC" ]   || die "systemd unit not found: $UNIT_SRC"

# --- Install the binary ------------------------------------------------------
info "installing binary -> ${PREFIX}/sbs-agent"
install -D -m 0755 "$BIN_SRC" "${PREFIX}/sbs-agent"

# --- Install the config (never clobber an existing one) ----------------------
install -d -m 0755 "$CONFIG_DIR"
if [ -e "${CONFIG_DIR}/agent.yaml" ]; then
  info "keeping existing ${CONFIG_DIR}/agent.yaml (installed a reference copy at agent.yaml.dist)"
  install -m 0640 "$CONFIG_SRC" "${CONFIG_DIR}/agent.yaml.dist"
else
  info "installing config -> ${CONFIG_DIR}/agent.yaml"
  install -m 0640 "$CONFIG_SRC" "${CONFIG_DIR}/agent.yaml"
fi

# --- State and log directories ----------------------------------------------
install -d -m 0750 "$STATE_DIR" "${STATE_DIR}/quarantine" "${STATE_DIR}/spool"
install -d -m 0755 "$LOG_DIR"

# --- Install the systemd unit ------------------------------------------------
info "installing unit -> ${UNIT_DIR}/${UNIT_NAME}"
install -m 0644 "$UNIT_SRC" "${UNIT_DIR}/${UNIT_NAME}"

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable "$UNIT_NAME" >/dev/null
  info "enabled ${UNIT_NAME}"
  if [ "$START" -eq 1 ]; then
    systemctl restart "$UNIT_NAME"
    info "started ${UNIT_NAME}"
  fi
else
  info "systemctl not found; skipped enabling the service (not a systemd host?)"
fi

cat <<EOF

install-agent.sh: done.

Next steps:
  1. Edit ${CONFIG_DIR}/agent.yaml — to upload to a server, set:
         server:
           url: https://sbs.example.com
           token: <SBS_AGENT_TOKEN, matching the server>
  2. Start / check the agent:
         sudo systemctl start sbs-agent
         systemctl status sbs-agent
         journalctl -u sbs-agent -f
  3. Alerts are written to ${LOG_DIR}/alerts.jsonl (see the 'alerts' key in the config).

Uninstall with: sudo ./scripts/uninstall-agent.sh
EOF
