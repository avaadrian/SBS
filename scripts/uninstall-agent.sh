#!/usr/bin/env bash
#
# uninstall-agent.sh — remove the sbs-agent systemd service and binary.
#
# Idempotent. Must run as root. By default it leaves your config and state
# (/etc/sbs, /var/lib/sbs, /var/log/sbs) in place.
#
#   sudo ./scripts/uninstall-agent.sh            # remove service + binary, keep data
#   sudo ./scripts/uninstall-agent.sh --purge    # also remove config, state and logs

set -euo pipefail

PREFIX=/usr/local/bin
CONFIG_DIR=/etc/sbs
STATE_DIR=/var/lib/sbs
LOG_DIR=/var/log/sbs
UNIT_DIR=/etc/systemd/system
UNIT_NAME=sbs-agent.service

PURGE=0

die() { echo "uninstall-agent.sh: $*" >&2; exit 1; }
info() { echo "uninstall-agent.sh: $*"; }

for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    -h|--help)
      sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) die "unknown argument: $arg" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo $0)"

if command -v systemctl >/dev/null 2>&1; then
  if systemctl list-unit-files "$UNIT_NAME" >/dev/null 2>&1; then
    systemctl stop "$UNIT_NAME" 2>/dev/null || true
    systemctl disable "$UNIT_NAME" 2>/dev/null || true
    info "stopped and disabled ${UNIT_NAME}"
  fi
fi

if [ -e "${UNIT_DIR}/${UNIT_NAME}" ]; then
  rm -f "${UNIT_DIR}/${UNIT_NAME}"
  info "removed ${UNIT_DIR}/${UNIT_NAME}"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
  fi
fi

if [ -e "${PREFIX}/sbs-agent" ]; then
  rm -f "${PREFIX}/sbs-agent"
  info "removed ${PREFIX}/sbs-agent"
fi

if [ "$PURGE" -eq 1 ]; then
  rm -rf "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR"
  info "purged ${CONFIG_DIR}, ${STATE_DIR}, ${LOG_DIR}"
else
  info "left config/state in place: ${CONFIG_DIR}, ${STATE_DIR}, ${LOG_DIR} (use --purge to remove)"
fi

info "done."
