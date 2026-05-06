#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Updating Ethernet Packet Lab..."
git pull --ff-only
npm install
chmod +x run-lab.sh update-lab.sh install-lab.sh
npm run check

cat <<'EOF'

Update complete.

Restart if already running:
  ./run-lab.sh
EOF
