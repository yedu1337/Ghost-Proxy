#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
chmod +x ./ghost-proxy 2>/dev/null || true

echo "Close the running Ghost Proxy window before changing these settings."
echo
./ghost-proxy --setup-only

printf '\nPress Enter to close...'
read -r _ || true
