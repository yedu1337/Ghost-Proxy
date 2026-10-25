#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Close the running gateway window before changing these settings."
echo
./ghost-proxy-server --setup-only

printf '\nPress Enter to close...'
read -r _ || true
