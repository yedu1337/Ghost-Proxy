# Synopsis implementation decisions

This document records places where the implementation intentionally extends
or differs from the original thesis synopsis. Update the submitted thesis to
match these decisions, or change the protocol before calling the project
specification-complete.

## Authentication order

The synopsis describes a server-first random challenge followed by a
client-generated HMAC response. Production uses client-first authentication:
the client sends a TLS-exporter-bound HMAC proof, and the gateway replies
with an authentication-success frame only after verification. This keeps the
gateway silent until application data arrives and lets it replay a failed
authentication attempt to the HTTP decoy. The old server-first helper remains
for compatibility tests only.

Decision: retain the client-first flow. The thesis protocol and sequence
diagram must be revised to describe it; do not describe the production flow
as challenge-response.

## ALPN

The synopsis lists `h2` and `http/1.1`. The Ghost client and gateway negotiate
only `http/1.1`, because the gateway does not implement HTTP/2. Adding `h2` to
the ALPN list without implementing HTTP/2 would misrepresent application
protocol support.

## Frame extensions and key separation

The implementation adds `TypeConnOpen (0x05)` and `TypeAuthSuccess (0x06)`
and uses separate client-to-server and server-to-client keys. Data-frame
associated data includes frame type, direction, and sequence number, and the
receiver rejects repeated or out-of-order sequence numbers. These are
protocol extensions beyond the synopsis and are described in
`docs/protocol.md`.

## Decoy limits

The bundled Nginx decoy speaks plain HTTP. The gateway can hand off raw HTTP
and HTTP/1.1 requests after a successful TLS handshake when authentication
parsing fails. It cannot transparently continue an arbitrary failed TLS
handshake to a plain HTTP listener. A TLS-capable decoy path and packet-level
tests are still required to claim arbitrary TLS-probe fallback.

## TLS fingerprint claims

The client uses a uTLS Chrome-style profile, but there are no checked-in
Chrome/Ghost packet captures or JA3/JA4 comparisons. The project must not
claim a Chrome-identical fingerprint until the procedure in
`docs/fingerprint.md` has been run and its evidence recorded.
