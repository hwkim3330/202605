#!/usr/bin/env bash
# Ethernet Packet Lab — runner
# Starts the local Node server with raw-socket capability via sudo.
set -euo pipefail

cd "$(dirname "$0")"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This lab needs Linux AF_PACKET raw sockets. Detected: $(uname -s)" >&2
  exit 1
fi

NODE_BIN="$(command -v node || true)"
NPM_BIN="$(command -v npm || true)"
PY_BIN="$(command -v python3 || true)"

if [[ -z "$NODE_BIN" || -z "$NPM_BIN" ]]; then
  echo "node/npm not found. Run ./install-lab.sh first." >&2
  exit 1
fi
if [[ -z "$PY_BIN" ]]; then
  echo "python3 not found. The packet agent needs Python 3.10+. Run ./install-lab.sh." >&2
  exit 1
fi

NODE_DIR="$(dirname "$NODE_BIN")"
RUN_PATH="$NODE_DIR:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

if [[ ! -d node_modules && -f package-lock.json ]]; then
  echo "node_modules missing — running npm install…"
  npm install --silent
fi

PORT="${PORT:-8080}"
if ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
  echo "Port ${PORT} already in use — another lab instance is probably running." >&2
  echo "Stop it first:  sudo pkill -f 'node .*server.js'" >&2
  exit 1
fi

if [[ "${EUID}" -eq 0 ]]; then
  env PATH="$RUN_PATH" PORT="$PORT" npm start
else
  echo "Starting with sudo for CAP_NET_RAW (packet send/capture requires root)…"
  exec sudo --preserve-env=PORT env PATH="$RUN_PATH" PORT="$PORT" npm start
fi
