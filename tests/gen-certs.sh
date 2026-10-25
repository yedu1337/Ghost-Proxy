#!/usr/bin/env sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$repo/configs"
openssl req -config "$repo/tests/openssl.cnf" -extensions v3_req \
  -x509 -newkey rsa:2048 -sha256 -nodes -days 30 \
  -keyout "$repo/configs/server.key" \
  -out "$repo/configs/server.crt"
chmod 644 "$repo/configs/server.crt"
chmod 644 "$repo/configs/server.key" # local test credential only
echo "Created local-only configs/server.crt and configs/server.key"
