#!/usr/bin/env bash
# Ethernet Packet Lab — installer
# Verifies prerequisites (Linux, Node 18+, Python 3.10+, iproute2),
# installs npm dependencies, and prepares the helper scripts.
set -euo pipefail

cd "$(dirname "$0")"

err()  { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }
ok()   { printf '\033[1;32m%s\033[0m\n' "$*"; }
info() { printf '\033[1;34m%s\033[0m\n' "$*"; }

# --- platform check
if [[ "$(uname -s)" != "Linux" ]]; then
  err "This lab uses Linux AF_PACKET raw sockets. Detected: $(uname -s)"
  err "macOS / Windows are not supported. Run on Ubuntu / Debian / RHEL / Arch / etc."
  exit 1
fi

# --- node 18+
if ! command -v node >/dev/null 2>&1; then
  err "node not found. Install Node.js 18 or newer (https://nodejs.org/)"
  err "  Ubuntu/Debian: curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt install -y nodejs"
  exit 1
fi
NODE_VER="$(node -v | sed 's/^v//')"
NODE_MAJOR="${NODE_VER%%.*}"
if (( NODE_MAJOR < 18 )); then
  err "node v${NODE_VER} is too old. Need Node.js 18+ (the server uses native fetch + ReadableStream)."
  exit 1
fi
ok "node v${NODE_VER}"

# --- npm
if ! command -v npm >/dev/null 2>&1; then
  err "npm not found. Install npm (usually bundled with Node.js)."
  exit 1
fi
ok "npm $(npm -v)"

# --- python 3.10+
PY="$(command -v python3 || true)"
if [[ -z "$PY" ]]; then
  err "python3 not found. Install Python 3.10+."
  err "  Ubuntu/Debian: sudo apt install python3"
  exit 1
fi
PY_VER="$("$PY" -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_MAJOR="${PY_VER%%.*}"
PY_MINOR="${PY_VER##*.}"
if (( PY_MAJOR < 3 || (PY_MAJOR == 3 && PY_MINOR < 10) )); then
  err "python ${PY_VER} too old. Need Python 3.10+ (uses PEP 604 union types and time.time_ns)."
  exit 1
fi
ok "python ${PY_VER}"

# --- iproute2 (used by agent to enumerate interfaces)
if ! command -v ip >/dev/null 2>&1; then
  err "ip(8) not found. Install iproute2."
  err "  Ubuntu/Debian: sudo apt install iproute2"
  exit 1
fi
ok "iproute2: $(ip -V 2>&1 | head -n1)"

# --- raw socket / sudo hint
if ! sudo -n true 2>/dev/null; then
  info "Note: ./run-lab.sh will prompt for sudo (raw socket needs CAP_NET_RAW)."
fi

# --- install dependencies
info "Installing npm dependencies (no native modules)…"
npm install --silent

chmod +x run-lab.sh update-lab.sh install-lab.sh

if npm run --silent check >/tmp/lab-check.log 2>&1; then
  ok "syntax check passed (npm run check)"
else
  err "npm run check failed:"
  tail -n 30 /tmp/lab-check.log >&2
  exit 1
fi

cat <<'EOF'

✅  Install complete.

Run:
    ./run-lab.sh

Open on this PC:
    http://localhost:8080

Two-PC link tests
    Install and run this repository on BOTH PCs (one acts as Sender, the other as Receiver).
    On each PC the local browser controls only that machine's NICs.
    Pin the Peer URL in the top link strip — see README.
EOF
