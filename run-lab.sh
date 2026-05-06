#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

NODE_BIN="$(command -v node || true)"
NPM_BIN="$(command -v npm || true)"

if [[ -z "$NODE_BIN" || -z "$NPM_BIN" ]]; then
  echo "node/npm not found. Install Node.js 18+ first." >&2
  exit 1
fi

NODE_DIR="$(dirname "$NODE_BIN")"
RUN_PATH="$NODE_DIR:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

if [[ ! -d node_modules && -f package-lock.json ]]; then
  npm install
fi

if [[ "${EUID}" -eq 0 ]]; then
  env PATH="$RUN_PATH" npm start
else
  echo "Starting with sudo for CAP_NET_RAW packet send/capture..."
  exec sudo env PATH="$RUN_PATH" npm start
fi
