#!/usr/bin/env sh
set -eu

# Certbot runs deploy hooks only after successfully renewing a certificate.
systemctl restart ghost-proxy.service
