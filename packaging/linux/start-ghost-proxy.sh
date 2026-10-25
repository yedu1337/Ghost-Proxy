#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
chmod +x ./ghost-proxy 2>/dev/null || true
exec ./ghost-proxy "$@"
