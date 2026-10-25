# TLS fingerprint verification

The client currently builds a uTLS `HelloChrome_Auto` profile and removes
`renegotiation_info` to preserve TLS exporter access. The server advertises
only `http/1.1`, because this gateway does not implement HTTP/2.

Status: implemented, not verified. No Chrome or Wireshark capture is checked
into this repository, so the project does not claim that its ClientHello
matches stock Chrome and there are no JA3/JA4 values to report.

To collect reproducible evidence:

1. Record the Chrome version, uTLS module version, OS, destination, capture
   interface, and Wireshark/tshark version.
2. Capture a stock Chrome TLS 1.3 connection and a Ghost client TLS 1.3
   connection to the same hostname and network endpoint.
3. Save capture files outside the repository if they contain unrelated
   traffic; add sanitized captures or their SHA-256 hashes and the exact
   extraction commands to the evidence record.
4. Compare ClientHello extension order, cipher suites, supported groups, and
   ALPN, then report JA3 and JA4 values. The current profile removes
   `renegotiation_info` for TLS exporter compatibility and offers only
   `http/1.1`, so a perfect Chrome match is not expected without a protocol
   design change.

| Capture | Client version | JA3 | JA4 | ALPN | Capture hash |
|---|---|---|---|---|---|
| Stock Chrome | Not captured | Pending | Pending | Pending | Pending |
| Ghost client | Not captured | Pending | Pending | `http/1.1` | Pending |

Do not infer a match from the `HelloChrome_Auto` profile name.
