#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
chmod +x ./ghost-proxy 2>/dev/null || true

echo "Testing the connection through Ghost Proxy..."
echo

status=0
./ghost-proxy --check "$@" || status=$?

echo
if [ "$status" -eq 0 ]; then
  echo "Ghost Proxy is working."
else
  echo "The connection test failed. Read the message above, then try again."
fi

printf '\nPress Enter to close...'
read -r _ || true
exit "$status"
