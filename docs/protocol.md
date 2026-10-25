# Ghost Proxy wire protocol

This document describes the implementation in `pkg/frame`, `pkg/transport`,
`pkg/gateway`, and `pkg/client`. The client-first authentication lifecycle is
a deliberate deviation from the original synopsis: the gateway stays silent
until a client sends its first application frame, which permits decoy replay.

## Connection setup and authentication

1. A TCP connection is accepted. Its TLS 1.3 handshake runs in its own
   goroutine with a 10 second deadline. The client offers the `http/1.1` ALPN
   protocol; the gateway also selects only `http/1.1` because it does not
   implement HTTP/2. This intentionally differs from the synopsis's
   `h2/http1.1` ALPN list.
2. Both sides derive independent `c2s`, `s2c`, and `auth` keys with HKDF-SHA256.
   The TLS exporter is the HKDF salt and each key has its own versioned label.
3. The client's first TLS application frame is `TypeAuthResponse (0x02)`. Its
   ciphertext field contains `HMAC-SHA256(authKey,
   "ghost-protocol/client-first-auth/v1")`; no challenge or nonce is needed.
   A fresh exporter binds this proof to the TLS connection.
4. The gateway sends `TypeAuthSuccess (0x06)` only after constant-time proof
   verification. On parse or proof failure, it replays all consumed TLS
   application bytes and relays both directions to `fallback_address`.
   During TLS handshake failure it replays consumed TCP bytes to the fallback.

This project retains client-first authentication instead of the synopsis's
server challenge. It avoids sending a Ghost-specific challenge to ordinary
HTTPS clients before deciding whether their first application bytes belong to
the proxy or the HTTP decoy. The thesis specification should record this as an
approved protocol change. `Authenticate` remains as a deprecated server-first
compatibility helper for migration tests; production gateway handling calls
`AuthenticateReplay`.

The bundled fallback is plain HTTP. Raw HTTP sent to the TLS port can be
replayed to it, and an HTTP/1.1 request sent after a successful TLS handshake
can be relayed after authentication parsing fails. A malformed TLS handshake
cannot be made transparent by replaying its bytes to an HTTP listener: the
gateway may already have sent a TLS alert. Arbitrary TLS-probe camouflage
therefore remains incomplete and needs a TLS-capable decoy/proxy design plus
network capture evidence.

## Frame format

Each frame is one write containing this 15-byte header followed by ciphertext:

| Field | Size | Meaning |
|---|---:|---|
| Type | 1 byte | Frame type below |
| Length | 2 bytes | Ciphertext length, unsigned big-endian |
| Nonce | 12 bytes | 4-byte random directional salt + 8-byte big-endian counter |
| Ciphertext | Length bytes | ChaCha20-Poly1305 output |

Frame types are `0x01` authentication challenge (deprecated), `0x02`
authentication response, `0x03` data payload, `0x04` connection close,
`0x05` connection open, and `0x06` authentication success. Types `0x05` and
`0x06` were added after the synopsis and are protocol extensions.

For data frames, the AEAD associated data is the type, direction byte, and
counter. Receivers require counters to arrive starting at zero in sequence,
rejecting repeats and reordering. The two directions use different HKDF keys.
The encrypted plaintext contains a two-byte payload length, payload, and
optional random padding to a 512, 1024, or 1460 byte ciphertext block.
The largest block plus its frame header and TLS 1.3 record overhead is 1497
bytes before IP/TCP headers, so it exceeds a 1500-byte MTU and is segmented by
TCP. See `docs/traffic-padding.md` for the capacity arithmetic.

## Destination policy

The gateway resolves destination names itself, rejects private, loopback,
link-local, unspecified, and multicast results, then dials one of the checked
IP literals. `allowed_destinations` optionally restricts targets further by
exact hostname/IP or CIDR. Domain names from SOCKS5 stay unresolved on the
client.

## Fingerprint and capture status

The client uses a uTLS Chrome-style ClientHello and both ends use only
`http/1.1` ALPN. The synopsis lists `h2/http1.1`; this project deliberately
omits `h2` because it is not an HTTP/2 server. See `docs/fingerprint.md` for
the outstanding packet-capture comparison. Source inspection is not
wire-level JA3/JA4 evidence.

Each SOCKS CONNECT currently creates its own TLS connection and authentication
exchange. A multiplexed long-lived tunnel has not been implemented.
