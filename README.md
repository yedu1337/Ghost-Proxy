# Ghost Proxy

Ghost Proxy is a self-hosted SOCKS5 proxy. A small client on your computer
opens an authenticated, encrypted tunnel to a gateway you control, and the
gateway forwards only the connections you request. It is designed for a
trusted group of users who need a private exit point without a complicated
control panel.

- **Guided setup** — the client asks for the server address, certificate, and
  key on first run. No YAML editing is required.
- **Free trusted TLS** — the Linux installer can obtain a Let's Encrypt
  certificate for a **public IP address**, so you do not need to buy a domain.
- **Automatic renewal** — Linux installations renew the certificate with a
  systemd timer and reload the gateway.
- **Connection check** — `--check` makes a real HTTP request through the
  tunnel and explains common failures.
- **Single binary** — the client and gateway are Go binaries with no runtime
  dependencies.

The project is MIT-licensed. See [LICENSE](LICENSE).

## Use Ghost Proxy (clients)

Download the package for your computer from
**[Releases](https://github.com/yedukrishna012/Ghost-Proxy/releases/latest)**:

| System | Download | Start |
| --- | --- | --- |
| Windows 10/11 (64-bit) | `GhostProxy-Client-Windows-x64.zip` | Double-click `GhostProxy.exe` |
| Linux (64-bit x86_64) | `GhostProxy-Client-Linux-x64.tar.gz` | Run `./start-ghost-proxy.sh` |

1. Extract the package to a folder you can write to, such as Desktop or
   Documents. Do not run it from inside the archive.
2. Start Ghost Proxy as shown above.
3. On first run, the setup wizard asks for:
   - **Server address** — the gateway address from your provider, written as
     `host:port`, for example `203.0.113.10:443` or
     `proxy.example.com:443`.
   - **TLS server name** — press Enter to use the same host name.
   - **CA certificate** — leave blank when the gateway uses a publicly trusted
     certificate (the Linux installer does). If your provider gave you a
     `server.crt` file, enter its full path; the client copies it into its
     settings folder.
   - **PSK** — the hexadecimal key from your provider. It is stored locally in
     `ghost.env` and never uploaded.
4. Leave the Ghost Proxy window open while you browse.

### Test the connection

Use the included test launcher:

- **Windows:** double-click `Test Ghost Proxy.bat`.
- **Linux:** run `./test-ghost-proxy.sh`.

Or run the client directly:

```bash
./ghost-proxy --check
```

The check opens a real HTTP request to `example.com:80` through the gateway.
If the gateway only permits certain destinations, choose one of them:

```bash
./ghost-proxy --check --check-target allowed.example:80
```

### Connect your browser

Ghost Proxy does **not** change your system proxy settings. Configure your
browser or app to use the local SOCKS5 proxy:

| Setting | Value |
| --- | --- |
| Proxy type | SOCKS5 |
| Host | `127.0.0.1` |
| Port | `1080` |

- **Firefox:** Settings → Network Settings → Manual proxy configuration →
  SOCKS Host `127.0.0.1`, Port `1080`, SOCKS v5.
- **Chrome/Edge:** use the operating system proxy settings, or launch the
  browser with `--proxy-server="socks5://127.0.0.1:1080"`.
- **Windows:** Settings → Network & Internet → Proxy → Manual proxy setup →
  SOCKS5 `127.0.0.1:1080`.

### Change settings later

- **Windows:** close Ghost Proxy, then double-click
  `GhostProxy Settings.bat`.
- **Linux:** close Ghost Proxy, then run `./ghost-proxy-settings.sh`.

The wizard remembers the previous answers. Press Enter to keep a value.

### Client notes

- Windows builds are unsigned. SmartScreen may show a warning; choose
  **More info → Run anyway**.
- Never share your PSK or `ghost.env`.
- The client listens only on `127.0.0.1:1080` by default.

## Run a gateway (operators)

### Recommended: Linux VPS, one command, no domain required

A Linux VPS is a rented server with a public IP address (for example an AWS
EC2 instance, Hetzner, DigitalOcean, or Oracle Cloud). The recommended setup
is:

1. **Create the server** with a current 64-bit Linux image. The installer
   supports Debian 12/Ubuntu 22.04 or newer, Amazon Linux 2023, and Fedora.
   Certbot needs Python 3.10 or newer; on Amazon Linux the installer adds
   Python 3.11 automatically when the default Python is too old.
2. **Open inbound TCP 80 and 443** in your cloud firewall/security group.
   - Port 443 carries the gateway.
   - Port 80 is used by Let's Encrypt for issuance and renewal. Keep it open.
   - Keep SSH (usually port 22) open so you can log in.
3. **Download and extract** the server package into its own folder, then run
   the installer:

   ```bash
   mkdir -p ghost-proxy-server
   cd ghost-proxy-server
   curl -LO https://github.com/yedukrishna012/Ghost-Proxy/releases/latest/download/GhostProxy-Server-Linux-x64.tar.gz
   tar -xzf GhostProxy-Server-Linux-x64.tar.gz
   sudo ./install.sh
   ```

   If you downloaded the package another way, extract it into an empty folder
   and run `sudo ./install.sh` from that folder. The archive extracts its files
   directly, so there is no inner `GhostProxy-Server-Linux-x64` directory.

   The installer detects the server's public IP and offers it as the default.
   Press Enter to accept it. A domain is **not** required. An email address is
   optional and is used for Let's Encrypt expiry notices.

4. **Send the invite** printed at the end to each user privately. It is also
   saved on the server at:

   ```text
   /etc/ghost-proxy/invite.txt
   ```

The installer obtains a free Let's Encrypt certificate for the public IP
address and sets up automatic renewal. Let's Encrypt IP certificates are
short-lived (about six days), so the renewal timer runs daily and port 80 must
remain reachable.

> **Keep the IP address stable.** An IP certificate is tied to the address
> users connect to. On AWS, attach an Elastic IP (or use a static IP from your
> provider) so the address does not change when the instance stops and starts.
> If the public IP changes, rerun the installer with the new address.

### What the installer sets up

| Path or service | Purpose |
| --- | --- |
| `/opt/ghost-proxy/ghost-proxy-server` | Gateway binary |
| `/etc/ghost-proxy/server.yaml` | Server configuration |
| `/etc/ghost-proxy/environment` | `GHOST_PSK` environment file, root/service only |
| `/etc/ghost-proxy/server.crt` | Active certificate chain |
| `/etc/ghost-proxy/server.key` | Active private key, root/service only |
| `/etc/ghost-proxy/invite.txt` | Ready-to-send user invite, root only |
| `/etc/ghost-proxy/renewal-cert-name` | Let's Encrypt lineage watched by the renewal hook |
| `ghost-proxy.service` | Unprivileged systemd service on the chosen port (443 by default) |
| `ghost-proxy-certbot-renew.timer` | Daily certificate renewal |
| `/opt/certbot` | Private Certbot environment (5.4 or newer) |

If the gateway is reinstalled, the existing public host, PSK, public port,
fallback address, and allowed destinations are kept. Let's Encrypt renewal stays
enabled. The certificate is reused when it is still valid and covers the
public host.

### Use a domain instead of an IP

A domain is optional, but it is nicer to share and survives an IP change.
Point an `A` record (and `AAAA` if you use IPv6) at the server, then run:

```bash
sudo ./install.sh --host proxy.example.com --email you@example.com
```

The installer requests a normal Let's Encrypt domain certificate and configures
the same automatic renewal.

> **Free subdomains:** services such as DuckDNS and sslip.io share one
> registered domain across many users, so Let's Encrypt rate limits can make
> them unreliable. A public-IP certificate avoids that problem entirely and is
> the simplest path when you do not own a domain.

### Manage the gateway

```bash
# Status and recent logs
sudo systemctl status ghost-proxy
sudo journalctl -u ghost-proxy -n 50 --no-pager

# Restart or stop
sudo systemctl restart ghost-proxy
sudo systemctl stop ghost-proxy

# Reprint the invite after changing settings
sudo /opt/ghost-proxy/ghost-proxy-server --show-invite \
  --config /etc/ghost-proxy/server.yaml \
  --env-file /etc/ghost-proxy/environment

# Test the saved configuration without starting the gateway
sudo /opt/ghost-proxy/ghost-proxy-server --check \
  --config /etc/ghost-proxy/server.yaml \
  --env-file /etc/ghost-proxy/environment
```

**Rotate the shared PSK** after a leak or when someone leaves:

Run this from the folder where you extracted the server package:

```bash
sudo ./install.sh --new-psk
```

If you no longer have that folder, download and extract the package again
first.

This generates a new key, restarts the gateway, and prints a new invite. Every
user must update their client with the new key; the old key stops working when
the gateway restarts. Send the new invite privately.

**Upgrade the gateway:** download the new Linux server package, extract it into
a folder, and run `sudo ./install.sh` from that folder. The installer keeps the
PSK and existing settings, replaces the binary, and restarts the service.

### AWS and firewall examples

In the AWS EC2 console, edit the instance's security group and add inbound
rules:

| Type | Port | Source |
| --- | --- | --- |
| SSH | 22 | Your IP address |
| HTTP | 80 | `0.0.0.0/0` (and `::/0` for IPv6) |
| Custom TCP | 443 | `0.0.0.0/0` (and `::/0` for IPv6) |

On the server itself, if UFW is active:

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

If firewalld is active:

```bash
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --reload
```

Other cloud providers have an equivalent firewall or security-group page. The
installer prints the exact commands for a detected host firewall, but it does
not change cloud security groups. If you installed the gateway with a custom
`--port`, allow that port instead of 443.

### Windows gateway (manual)

The Linux installer is recommended for a public gateway. A Windows computer
can run the gateway for testing or a small private group:

1. Download and unzip `GhostProxy-Server-Windows-x64.zip`.
2. Double-click `start-ghost-proxy-server.bat`.
3. The setup wizard asks for the public host and port, the TLS certificate,
   and generates a PSK.
   - Use an existing certificate and key if you have one.
   - A self-signed certificate is fine for testing, but each user must enter
     the provided `configs/server.crt` as the CA certificate in the client.
4. Forward TCP 443 on your router to the computer, and keep the computer
   running while users need access.

Use `GhostProxy Server Settings.bat` to change settings later. For a public
service, a Linux VPS with a trusted certificate is easier and more reliable.

### Manual Linux systemd install (advanced)

The one-command installer is recommended. If you need to install the gateway
manually, follow
[`deployments/systemd/README.md`](deployments/systemd/README.md). It covers
the service account, file permissions, Certbot 5.4 or newer, the systemd
units, and the renewal timer.

## Configuration reference

### Server

```yaml
listen_address: "0.0.0.0:443"
public_host: "203.0.113.10"     # host or IP users connect to; used in invites
log_level: "info"
cert_file: "/etc/ghost-proxy/server.crt"
key_file: "/etc/ghost-proxy/server.key"
fallback_address: ""            # optional plain-HTTP decoy, e.g. "127.0.0.1:8080"
allowed_destinations: []        # empty = all public destinations; or hosts/CIDRs
padding_enabled: true
jitter_ms: 0
pprof_address: ""               # keep empty in production
```

`public_host` is used when printing the invite and when checking that the
certificate covers the address users connect to. `allowed_destinations`
restricts the gateway to exact hosts/IPs or CIDRs; private, loopback,
link-local, and unspecified destinations are always rejected.

The PSK is read from `GHOST_PSK` in the environment, or from the file passed
with `--env-file`. The Linux installer stores it in
`/etc/ghost-proxy/environment`.

### Client

The setup wizard writes this for you. The equivalent fields are:

```yaml
listen_address: "127.0.0.1:1080"
server_address: "203.0.113.10:443"
server_name: "203.0.113.10"
ca_file: ""                     # blank for a publicly trusted certificate
log_level: "info"
padding_enabled: true
jitter_ms: 0
```

For a self-signed gateway, set `ca_file` to the provided `server.crt`. A
relative path is resolved relative to the client configuration file.

## How it works

```text
Application
    |
    v
Local SOCKS5 client (127.0.0.1:1080)
    |
    | SOCKS5 CONNECT
    v
Ghost client
    |
    | TLS 1.3 + authenticated Ghost protocol
    v
Ghost gateway
    |
    | authenticated destination forwarding
    v
Requested TCP destination
```

The gateway and client authenticate with a shared PSK over a TLS 1.3
connection. Session keys are derived from the TLS exporter; data frames are
encrypted with ChaCha20-Poly1305 and bound to their direction and sequence
number. Padding and optional jitter blur frame sizes and timing.

The gateway resolves each destination, rejects private or local addresses,
and dials the checked IP. Unauthenticated connections can be forwarded to an
optional HTTP decoy, which makes the gateway look like an ordinary web server
to scanners. See [`docs/protocol.md`](docs/protocol.md) for the protocol and
[`docs/traffic-padding.md`](docs/traffic-padding.md) for traffic shaping.

### Security model and limitations

- **One shared PSK.** Every user has the same key. Anyone with it can use the
  gateway, and there is no per-user revocation. Rotate the PSK if it leaks.
- The PSK is the only access control, so send invites privately and never post
  them in a repository, chat room, or public issue.
- The gateway does not log browsing destinations by default, but the VPS
  provider and the destination services can still observe metadata.
- The client does not change system proxy settings or install a browser
  extension.
- Traffic padding is not a guarantee against a determined traffic-analysis
  adversary.
- IP certificates and short-lived certificates are a Let's Encrypt feature;
  keep Certbot current and port 80 reachable for renewal.

## Troubleshooting

### The client check fails

| Message | What to check |
| --- | --- |
| `The PSK does not match the gateway` | Copy the current PSK from the invite exactly. Ask the operator to reprint it with `--show-invite`. |
| `The TLS certificate could not be verified` | Check the server address and TLS server name. For a self-signed gateway, enter the provided `server.crt` in the client wizard. |
| `The gateway could not be reached` | Check the server address and that TCP 443 is open in the host firewall and cloud security group. Confirm the service is running. |
| `The gateway refused the test destination` | The gateway has an `allowed_destinations` list. Run `--check-target` with a permitted `host:port`. |
| `no usable configuration found` | Run the client from a terminal or the packaged launcher so the first-run wizard can start. |

### The browser cannot reach sites

- Confirm Ghost Proxy is still running and its window has no error.
- Confirm the browser is set to SOCKS5 `127.0.0.1:1080`, not an HTTP proxy.
- Try the included connection check before changing browser settings.
- Some applications ignore the system proxy; configure the SOCKS5 proxy inside
  that application.

### The gateway will not start

```bash
sudo systemctl status ghost-proxy
sudo journalctl -u ghost-proxy -n 100 --no-pager
sudo /opt/ghost-proxy/ghost-proxy-server --check \
  --config /etc/ghost-proxy/server.yaml \
  --env-file /etc/ghost-proxy/environment
```

Common causes are a missing or unreadable private key, a certificate that does
not cover `public_host`, an invalid PSK, or another service already using port
443.

### Certificate issuance fails

- Port 80 must be open in the cloud security group **and** the host firewall.
- No other web server (nginx, Apache, Caddy) may be listening on port 80
  during standalone validation.
- For a domain, its DNS record must point to the server before you run the
  installer.

### Windows SmartScreen

The Windows binaries are not code-signed. Choose **More info → Run anyway**.
Only download them from the official Releases page.

## Build from source

Requirements: a Go toolchain compatible with `go.mod`, plus OpenSSL for local
test certificates.

```bash
git clone https://github.com/yedukrishna012/Ghost-Proxy.git
cd Ghost-Proxy

go build -o ghost-proxy ./cmd/client
go build -o ghost-proxy-server ./cmd/server

go test ./... -count=1
go vet ./...
```

### Local test with a self-signed certificate

```bash
sh tests/gen-certs.sh

export GHOST_PSK=$(openssl rand -hex 32)
./ghost-proxy-server --setup-only --self-signed \
  --config configs/server.yaml --env-file ghost.env \
  --public-host localhost --public-port 8443 --non-interactive
./ghost-proxy-server --config configs/server.yaml --env-file ghost.env
```

In another terminal, create a client configuration pointing at
`localhost:8443` with `ca_file: configs/server.crt`, then run:

```bash
./ghost-proxy --check --config configs/client.yaml
```

### Cross-compilation and packages

The release workflow builds Windows and Linux packages from tags matching
`v*`. To reproduce locally:

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o GhostProxy.exe ./cmd/client
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o ghost-proxy ./cmd/client
```

See [`.github/workflows/release.yml`](.github/workflows/release.yml) for the
exact package contents and checksums.

## Advanced deployments

- **Docker Compose:** [`deployments/compose.yml`](deployments/compose.yml) and
  [`configs/`](configs/) contain a client/gateway/decoy setup for testing.
- **Nginx decoy:** [`deployments/nginx/`](deployments/nginx/) and
  [`docs/nginx-decoy-setup.md`](docs/nginx-decoy-setup.md).
- **Protocol and design:** [`docs/protocol.md`](docs/protocol.md),
  [`docs/fingerprint.md`](docs/fingerprint.md),
  [`docs/thesis-deviations.md`](docs/thesis-deviations.md),
  [`docs/performance.md`](docs/performance.md),
  [`docs/socks5.md`](docs/socks5.md).
- **systemd and Certbot:** [`deployments/systemd/README.md`](deployments/systemd/README.md).

## License

MIT License. Copyright (c) 2026 Yedukrishna R (@yedukrishna012).
