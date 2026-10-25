# Ghost Proxy change summary

## Synopsis gap closure (2026-10-04)

- Added loopback-only, opt-in pprof for the gateway and configuration checks
  preventing profiling endpoints from binding to public interfaces.
- Added a repeatable in-memory data-frame benchmark and profiling guidance.
- Added pinned Staticcheck to CI and suppression comments for tests that
  intentionally exercise the legacy server-first authentication helper.
- Added pre-TLS HTTP preface detection so raw HTTP probes reach the configured
  HTTP decoy without first receiving a TLS alert. Extended the Linux Compose
  E2E script to check raw HTTP and unauthenticated HTTPS fallback.
- Added a Certbot deploy hook to restart systemd after certificate renewal.
- Documented the production client-first authentication flow, HTTP/1.1-only
  ALPN choice, and the limitation that malformed TLS cannot transparently
  continue through a plain HTTP decoy.
- Recorded a preliminary codec benchmark: 4.588 µs/op, 111.60 MB/s,
  6,992 B/op, 13 allocs/op on Windows/amd64, Go 1.27.0, AMD Ryzen 7 7435HS.

### Verification for this branch

- `go test ./... -count=1` — passed.
- `go vet ./...` — passed.
- `go build ./...` — passed.
- `go run honnef.co/go/tools/cmd/staticcheck@2026.2.1 ./...` — passed.
- `go test ./pkg/transport -run '^$' -bench BenchmarkDataChannelRoundTrip -benchmem -count=1` — passed.
- `go test ./... -race -cover` — not runnable on this Windows host: its MinGW
  `cc1.exe` reports that 64-bit mode is not compiled in.
- `tests/e2e-linux.sh` — not run: the Docker CLI is present but the Docker
  Desktop Linux engine is unavailable; no Linux shell is installed.
- Chrome/JA3/JA4 captures, malformed TLS decoy behavior, VPS deployment,
  multi-network field tests, and the final release remain outstanding.

## Gateway authentication and fallback

- Changed production authentication to client-first. The client sends an HMAC proof derived from the PSK and TLS exporter; the server waits for this frame before sending anything.
- Added `AuthenticateReplay`, which returns every consumed application byte to the configured fallback if the frame is malformed or the proof fails.
- Added fallback stream proxying with bidirectional copy, half-close handling, and five-minute idle deadlines.
- Moved TLS handshakes from listener `Accept()` into per-connection gateway goroutines. The server applies a 10-second handshake deadline and preserves bytes consumed during a failed handshake for fallback.
- Kept the old server-first `Authenticate` method as deprecated compatibility code for existing migration tests. The production server calls `AuthenticateReplay`.
- The gateway accept loop continues after temporary accept errors.

## Framing and cryptography

- `frame.WriteFrame` serializes the header and ciphertext into one buffer and performs one write.
- Added independent HKDF keys for client-to-server data and server-to-client data.
- Bound data-frame AEAD associated data to frame type, direction, and sequence number. Receivers reject repeated or out-of-order sequence numbers.
- Kept padding before AEAD sealing. Added `padding_enabled` and `jitter_ms` configuration support.
- Documented frame types `0x05` (connection open) and `0x06` (authentication success), which were missing from the synopsis.

## Destination and client configuration

- The gateway resolves destination hostnames, rejects private, loopback, link-local, unspecified, and multicast results, and dials the checked IP address.
- Added optional `allowed_destinations` hostname/IP/CIDR rules.
- Wired the client to `configs/client.yaml` for server address, SNI, CA file, SOCKS listen address, log level, padding, and jitter settings.
- TLS trust configuration is cached per client. An empty `ca_file` uses system roots; a configured relative CA path is resolved relative to the client config file.
- The client advertises only `http/1.1` in its TLS config. The server also advertises only `http/1.1`.
- The SOCKS listener refuses non-loopback binds unless `allow_remote_bind` is explicitly enabled.
- Added SOCKS request deadlines, accept-loop retry behavior, `slog` logging, and TCP half-close relay handling.

## Deployment, tests, and documentation

- Added `tests/gen-certs.sh` and its OpenSSL config, plus a Linux Compose E2E script.
- Added a Compose setup connecting the non-root gateway and client containers to a non-root Nginx decoy. Compose mounts local certificates instead of baking them into images.
- Added a systemd service example and Let’s Encrypt setup and renewal instructions.
- Added native fuzz targets for frame reading, unpadding, and SOCKS request parsing.
- Added tests for one-write framing, directional keys/AAD, replay and ordering rejection, private-destination rejection, concurrent per-connection setup, and wrong-PSK decoy fallback over TLS.
- Updated SOCKS, padding, Nginx, and protocol documentation. Added `docs/fingerprint.md` to record the missing capture evidence.
- Updated `.gitignore` for `ghost-client`, `*.exe`, `.env`, and local TLS test credentials.

## Verification performed

- `go test ./... -count=1 -timeout=90s` — passed.
- `go build ./...` — passed.
- `go vet ./...` — passed.
- Native fuzz smoke runs for `ReadFrame`, `Unpad`, and `readRequest` — passed.
- `docker compose -f deployments/compose.yml config --quiet` — passed.
- The Windows E2E PowerShell file parsed successfully.
- The equivalent OpenSSL command generated a localhost test certificate with the expected SAN entries.

## Checks still outstanding

- The Compose E2E was not run: the Docker CLI is present, but the Docker engine is unavailable, and this host has no usable Linux shell.
- `go test -race ./...` could not run because the installed C compiler does not support the required 64-bit mode.
- No Chrome/Wireshark capture was available. JA3/JA4 values and extension-order matching are not verified; see `docs/fingerprint.md`.
- A multiplexed long-lived tunnel is not implemented. Each SOCKS CONNECT still establishes its own TLS connection.
- `git ls-files` could not run because this workspace has no Git metadata. The ignore rules are updated, but tracked-file status for existing binaries and keys could not be confirmed.
