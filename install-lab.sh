#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v node >/dev/null 2>&1; then
  echo "node not found. Install Node.js 18+ first." >&2
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "npm not found. Install npm first." >&2
  exit 1
fi

npm install
chmod +x run-lab.sh update-lab.sh install-lab.sh
npm run check

cat <<'EOF'

Install complete.

Run:
  ./run-lab.sh

Open on this PC:
  http://localhost:8080

For two-PC tests, install and run this repository on BOTH PCs.
EOF
