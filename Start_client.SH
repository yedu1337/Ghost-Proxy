#!/usr/bin/env bash
# Ghost Proxy client launcher
# Usage: ./start-client.sh
# Put this file in the same directory as the ghost-client binary.

set -euo pipefail

cd "$(dirname "$0")"

# --- Config ---------------------------------------------------------
# Option A: hardcode here (simplest, but PSK ends up in this file --
#           do not commit it to git if you do this).
# GHOST_PSK="REPLACE_WITH_64_CHAR_HEX_PSK"

# Option B (recommended): keep the PSK in a local, gitignored file
# called ghost.env, one line: GHOST_PSK=yourhexkey
if [ -f "./ghost.env" ]; then
  # shellcheck disable=SC1091
  source ./ghost.env
fi

if [ -z "${GHOST_PSK:-}" ]; then
  echo "GHOST_PSK is not set."
  echo "Either edit this script and set GHOST_PSK directly, or create"
  echo "a file named ghost.env next to this script containing:"
  echo "  GHOST_PSK=your64characterhexkey"
  exit 1
fi

export GHOST_PSK

if [ ! -x "./ghost-client" ]; then
  echo "ghost-client binary not found or not executable in $(pwd)"
  exit 1
fi

echo "Starting ghost-client..."
./ghost-client