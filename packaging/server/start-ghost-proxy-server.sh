#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [ -f ./ghost.env ]; then
  set -a
  # shellcheck disable=SC1091
  source ./ghost.env
  set +a
fi

if [ -z "${GHOST_PSK:-}" ]; then
  echo "GHOST_PSK is not set."
  echo "Create ghost.env in this folder containing one line:"
  echo "  GHOST_PSK=your64characterhexkey"
  exit 1
fi

if [ ! -x ./ghost-proxy-server ]; then
  echo "ghost-proxy-server was not found or is not executable in $(pwd)."
  exit 1
fi

exec ./ghost-proxy-server "$@"
