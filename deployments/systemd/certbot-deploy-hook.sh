#!/usr/bin/env sh
set -eu

# Certbot runs this hook after a certificate is renewed. Only copy the
# certificate that belongs to this gateway; unrelated renewals must not
# replace the gateway certificate.
if [ -z "${RENEWED_LINEAGE:-}" ]; then
  echo "ghost-proxy renewal hook: RENEWED_LINEAGE is not set" >&2
  exit 1
fi

if [ ! -r /etc/ghost-proxy/renewal-cert-name ]; then
  exit 0
fi

expected=$(cat /etc/ghost-proxy/renewal-cert-name)
actual=$(basename "$RENEWED_LINEAGE")
if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
  exit 0
fi

install -m 0644 "$RENEWED_LINEAGE/fullchain.pem" /etc/ghost-proxy/server.crt
install -m 0640 -o root -g ghost-proxy "$RENEWED_LINEAGE/privkey.pem" /etc/ghost-proxy/server.key
systemctl try-restart ghost-proxy.service
