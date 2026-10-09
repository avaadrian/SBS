#!/usr/bin/env bash
#
# gen-tokens.sh — generate strong SBS tokens.
#
#   ./scripts/gen-tokens.sh            # print SBS_AGENT_TOKEN / SBS_CONSOLE_TOKEN lines
#   ./scripts/gen-tokens.sh --write    # create ./.env from .env.example with tokens filled in
#   ./scripts/gen-tokens.sh --write --force   # overwrite an existing .env
#
# Tokens are 32 random bytes, hex-encoded (256 bits). No secret is ever hardcoded.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)

WRITE=0
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --write) WRITE=1 ;;
    --force) FORCE=1 ;;
    -h|--help)
      sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "gen-tokens.sh: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

# Generate N random bytes as hex, using openssl if present, else /dev/urandom.
gen_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  elif command -v od >/dev/null 2>&1; then
    od -An -vtx1 -N32 /dev/urandom | tr -d ' \n'
  else
    echo "gen-tokens.sh: need 'openssl' or 'od' to generate tokens" >&2
    exit 1
  fi
}

AGENT_TOKEN=$(gen_token)
CONSOLE_TOKEN=$(gen_token)

if [ "$WRITE" -eq 0 ]; then
  cat <<EOF
SBS_AGENT_TOKEN=${AGENT_TOKEN}
SBS_CONSOLE_TOKEN=${CONSOLE_TOKEN}
EOF
  exit 0
fi

ENV_FILE="${REPO_ROOT}/.env"
EXAMPLE_FILE="${REPO_ROOT}/.env.example"

if [ -e "$ENV_FILE" ] && [ "$FORCE" -eq 0 ]; then
  echo "gen-tokens.sh: ${ENV_FILE} already exists; pass --force to overwrite" >&2
  exit 1
fi
if [ ! -f "$EXAMPLE_FILE" ]; then
  echo "gen-tokens.sh: ${EXAMPLE_FILE} not found" >&2
  exit 1
fi

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
# Substitute the two token lines; leave everything else as in the example.
sed \
  -e "s|^SBS_AGENT_TOKEN=.*|SBS_AGENT_TOKEN=${AGENT_TOKEN}|" \
  -e "s|^SBS_CONSOLE_TOKEN=.*|SBS_CONSOLE_TOKEN=${CONSOLE_TOKEN}|" \
  "$EXAMPLE_FILE" >"$TMP"
# Write with owner-only permissions — this file holds secrets.
umask 077
cp "$TMP" "$ENV_FILE"
chmod 600 "$ENV_FILE"

echo "gen-tokens.sh: wrote ${ENV_FILE} (mode 600) with fresh tokens"
echo "gen-tokens.sh: set the SAME SBS_AGENT_TOKEN as server.token in each agent's /etc/sbs/agent.yaml"
