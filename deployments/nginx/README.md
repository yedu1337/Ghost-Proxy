# Nginx Deployment

This directory contains the plain HTTP decoy used by the Compose harness and
the gateway's `fallback_address` after failed authentication or raw HTTP
probing. The gateway replays consumed application bytes to Nginx and relays
traffic in both directions.

## Docker

Build and start:

```powershell
docker build -t ghost-proxy-nginx .\deployments\nginx
docker run --rm -p 8080:8080 ghost-proxy-nginx
```

Verify the service:

```powershell
curl.exe http://127.0.0.1:8080/
curl.exe http://127.0.0.1:8080/health
```

The health endpoint should return:

```
ghost-nginx-ok
```

## Linux installation

Install Nginx using the package manager provided by the target Linux
distribution, then adapt the configuration in `nginx.conf` for the installed
Nginx layout.

The service should listen on the dedicated HTTP port configured for the
deployment and serve the controlled project page.

## Verification

Confirm:

1. Nginx starts without configuration errors.
2. TCP port 8080 is listening.
3. `GET /` returns HTTP 200.
4. `GET /health` returns HTTP 200 and `ghost-nginx-ok`.
5. The service is independently reachable from the test machine.

In the supplied Compose setup, the gateway uses `nginx:8080`. For a direct
deployment, set `fallback_address` to the private address of this listener,
such as `127.0.0.1:8080`.

Raw HTTP probes can be replayed to this listener. An HTTP/1.1 request sent
after a successful TLS handshake can also be handed off after Ghost
authentication parsing fails. This HTTP-only decoy cannot continue a failed
HTTPS handshake as TLS; the gateway may already have sent a TLS alert. See
`docs/protocol.md` for the current fallback limits.
