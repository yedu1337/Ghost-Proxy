# SOCKS5 local proxy

The client-side SOCKS5 listener accepts unauthenticated SOCKS5 CONNECT
requests and passes the destination to `pkg/client`. That client establishes
TLS 1.3 with uTLS, authenticates with the exporter-bound client-first proof,
and carries encrypted frames to the gateway. Domain names remain unresolved
until the gateway applies its destination policy. See [protocol.md](protocol.md).

## Listener and request handling

The listener defaults to `127.0.0.1:1080`. `cmd/client` refuses a non-loopback
bind unless the code is changed explicitly. Each accepted connection runs in
its own goroutine; transient accept errors are logged and retried, and closing
the listener ends the server cleanly.

The server negotiates only SOCKS5 `NO_AUTH`, then accepts CONNECT requests for
IPv4, domain, or IPv6 destinations. BIND and UDP ASSOCIATE are unsupported.
It returns connection-refused when the outbound tunnel cannot be established.
Malformed greetings and requests are closed after parsing fails.

Two `io.Copy` operations relay bytes in both directions. Each direction uses
TCP half-close when its source reaches EOF, allowing the other direction to
finish before both sockets are closed. SOCKS parsing deadlines are a separate
hardening item; the remote TLS and auth stages have bounded deadlines.

## Logging and coverage

The listener and per-connection errors use the shared `slog` logger. Tests in
`pkg/socks5` cover greeting negotiation, request parsing, replies, dialing,
relay behavior, and the integration flow. `FuzzReadRequest` provides a Go
native fuzz target for malformed request bytes.
