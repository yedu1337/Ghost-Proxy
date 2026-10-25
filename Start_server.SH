#!/usr/bin/env bash
# Ghost Proxy server launcher
# Usage: ./start-server.sh
# Put this file in the same directory as the ghost-server binary.

set -euo pipefail

cd "$(dirname "$0")"

if [ -f "./ghost.env" ]; then
  # shellcheck disable=SC1091
  source ./ghost.env
fi

if [ -z "${GHOST_PSK:-}" ]; then
  echo "GHOST_PSK is not set."
  echo "Create a file named ghost.env next to this script containing:"
  echo "  GHOST_PSK=your64characterhexkey"
  exit 1
fi

export GHOST_PSK

if [ ! -x "./ghost-server" ]; then
  echo "ghost-server binary not found or not executable in $(pwd)"
  exit 1
fi

echo "Starting ghost-server on 127.0.0.1:8443..."
./ghost-server -listen 127.0.0.1:8443