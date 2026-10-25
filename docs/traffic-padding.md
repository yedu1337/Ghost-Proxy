# Day 5 - Traffic Padding

## Overview

Ghost Proxy applies traffic-block padding to protected data frames before AEAD encryption. The padding layer normalizes ciphertext sizes into fixed block sizes so the original plaintext length is less directly visible from the encrypted frame size.

The implementation is located in:

* `pkg/padding/padding.go`
* `pkg/padding/padding_test.go`

Transport integration is located in:

* `pkg/transport/data.go`

## Padding Configuration

The current padding configuration uses three fixed wire-size targets:

* 512 bytes
* 1024 bytes
* 1460 bytes

These values are defined by `pkg/padding.BlockSizes`.

The smallest configured block that can contain the plaintext envelope plus AEAD overhead is selected automatically.

Padding can be enabled or disabled with `padding_enabled` and write jitter can
be set with `jitter_ms` in YAML. The supported block sizes remain defined in
`pkg/padding/padding.go`.

## Frame Size and Capacity

The protected transport uses ChaCha20-Poly1305 with a 16-byte AEAD authentication tag. A 1460-byte ciphertext plus the 15-byte frame header and 22-byte TLS 1.3 record overhead is 1497 bytes before IP/TCP headers, so that block exceeds a 1500-byte path MTU and TCP splits it across segments. No packet capture was available to verify actual segmentation on a particular network.

| Wire block | AEAD overhead | Envelope capacity | Maximum payload |
| ---------- | ------------- | ----------------- | --------------- |
| 512 bytes  | 16 bytes      | 496 bytes         | 494 bytes       |
| 1024 bytes | 16 bytes      | 1008 bytes        | 1006 bytes      |
| 1460 bytes | 16 bytes      | 1444 bytes        | 1442 bytes      |

The envelope contains a two-byte big-endian payload-length prefix.

Payloads larger than 1442 bytes cannot fit in the current padding configuration and are rejected with `ErrEnvelopeTooLarge`.

## Processing Pipeline

Padding is applied to the plaintext envelope before AEAD sealing:

`EncodePayload -> Pad -> Seal -> WriteFrame`

On reception, the reverse operation is performed:

`ReadFrame -> Open -> Unpad -> DecodePayload`

Padding must be applied before encryption. Appending padding after encryption would change the protected frame structure and prevent the receiver from correctly validating and decrypting the data.

## Padding Format

The original encoded envelope remains unchanged at the beginning of the padded plaintext.

```text
+----------------------+-------------------+----------------------+
| 2-byte payload len   | original payload  | random padding bytes |
+----------------------+-------------------+----------------------+
```

During unpadding, the receiver reads the length prefix and returns exactly the original envelope bytes. The padding bytes are discarded.

## Malformed Padding Handling

`Unpad` validates post-decryption data before returning the original envelope.

The following malformed inputs are rejected:

* Fewer than two bytes: `ErrEnvelopeTooShort`
* A length prefix larger than the received envelope: `ErrLengthPrefixInvalid`

The implementation is also tested to ensure garbage input does not cause a panic.

Oversized plaintext envelopes are rejected by `Pad` with `ErrEnvelopeTooLarge`.

## Measured Overhead

Padding overhead depends on the original payload size and the selected block.

| Application payload | Selected block | Padded plaintext | Ciphertext |
| ------------------- | -------------- | ---------------- | ---------- |
| 1 byte              | 512 bytes      | 496 bytes        | 512 bytes  |
| 100 bytes           | 512 bytes      | 496 bytes        | 512 bytes  |
| 494 bytes           | 512 bytes      | 496 bytes        | 512 bytes  |
| 495 bytes           | 1024 bytes     | 1008 bytes       | 1024 bytes |
| 1006 bytes          | 1024 bytes     | 1008 bytes       | 1024 bytes |
| 1007 bytes          | 1460 bytes     | 1444 bytes       | 1460 bytes |
| 1442 bytes          | 1460 bytes     | 1444 bytes       | 1460 bytes |

For example, both a 100-byte payload and a 494-byte payload produce a 512-byte ciphertext frame.

## Random Filler

Padding bytes are generated using `crypto/rand` rather than deterministic or zero-filled data.

The test suite includes a smoke test that rejects an all-zero padding region.

## Test Coverage

The padding package tests cover:

* Smallest-fitting block selection
* Exact block boundaries
* Oversized envelopes
* Exact-fit payloads with no filler
* Successful pad/unpad round trips
* Different payload sizes landing in the same padding bucket
* Malformed length prefixes
* Inputs that are too short
* Garbage input without panics
* Random filler behavior

Transport tests additionally exercise padding through the protected data transport.

The protected transport pipeline is:

`Encode -> Pad -> AEAD Seal -> Frame Write`

and:

`Frame Read -> AEAD Open -> Unpad -> Decode`

## Current Limitations

The current implementation uses fixed block sizes:

* 512 bytes
* 1024 bytes
* 1460 bytes

These are not currently exposed as runtime YAML configuration.

The maximum supported application payload in one padded data frame is 1442 bytes. Larger payloads require higher-level fragmentation or a future extension to the padding configuration.

## Day 5 Acceptance Summary

| Requirement                            | Status                                    |
| -------------------------------------- | ----------------------------------------- |
| Supported payload sizes round-trip     | Implemented and tested                    |
| Malformed padding rejected             | Implemented and tested                    |
| Padding works with protected transport | Integrated and tested                     |
| Configuration documented               | Fixed block-size configuration documented |
| Measured overhead documented           | Included above                            |
