# Nginx Deployment Setup

## Purpose

Ghost Proxy includes a separately configured Nginx web service for controlled
deployment and testing.

The gateway relays a TLS client's application stream to the configured
`fallback_address` after authentication fails. In Compose that address is
`nginx:8080`; configure Nginx separately and keep the fallback private to the
container network. This is HTTP after the gateway's TLS termination. Failed
TLS handshakes replay their consumed TCP bytes to the configured upstream.

For the containerized project setup, Nginx listens on:

- Compose service address: `nginx`
- Container port: `8080`
- Default Docker host port in the examples: `8080`

## Docker deployment

From the repository root:

```powershell
docker build -t ghost-proxy-nginx .\deployments\nginx
docker run --rm -p 8080:8080 ghost-proxy-nginx
```

Verify the landing page:

```powershell
curl.exe -i http://127.0.0.1:8080/
```

Verify the health endpoint:

```powershell
curl.exe -i http://127.0.0.1:8080/health
```

Expected health response:

```
ghost-nginx-ok
```

## Automated verification

Run the project-provided PowerShell health test:

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\nginx-health.ps1
```

The test builds the Nginx image, starts a temporary container on host port
`18080`, checks the root page and health endpoint, verifies that the
container is running, and removes the temporary resources.

A successful run ends with:

```
NGINX HEALTH TEST: PASS
```

## Native Linux installation

For a host-based Nginx installation, install Nginx with the package manager
provided by the target Linux distribution.

The repository's container configuration is the reproducible reference setup.
Adapt the paths and service-management commands to the host distribution.

## Deployment notes

Keep Nginx independently configured from the Ghost gateway. Use a controlled
web page and controlled test environment for project demonstrations.

The source tests verify wrong-key byte replay and a decoy response. Run
`tests/e2e-linux.sh` to exercise the Compose topology on Linux with Docker and
network access.
