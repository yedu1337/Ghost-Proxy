// The plaintext envelope carried inside a Frame's ciphertext, per the wire
// format spec:
//
//	+-----------------------+--------------------+
//	| Original Length (2B)  | Payload (N bytes)   |
//	+-----------------------+--------------------+
//
// pkg/crypto seals EncodePayload's output and, after opening a
// ciphertext, hands the plaintext to DecodePayload.
package frame

import (
	"encoding/binary"
	"fmt"
)

// MaxPayloadLen is the largest payload representable in the 2-byte
// Original Data Length field.
const MaxPayloadLen = 1<<16 - 1

// EncodePayload prepends payload's length as a 2-byte big-endian prefix,
// producing the plaintext envelope that gets AEAD-sealed into a Frame's
// Ciphertext.
func EncodePayload(payload []byte) ([]byte, error) {
	if len(payload) > MaxPayloadLen {
		return nil, fmt.Errorf(
			"frame: payload too large: %d bytes (max %d)",
			len(payload), MaxPayloadLen,
		)
	}

	envelope := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(envelope[:2], uint16(len(payload)))
	copy(envelope[2:], payload)

	return envelope, nil
}

// DecodePayload reverses EncodePayload: given a plaintext envelope (the
// output of pkg/crypto's Open), it validates the length prefix and
// returns the original payload bytes.
func DecodePayload(envelope []byte) ([]byte, error) {
	if len(envelope) < 2 {
		return nil, fmt.Errorf("frame: envelope too short: %d bytes", len(envelope))
	}

	length := binary.BigEndian.Uint16(envelope[:2])
	rest := envelope[2:]

	if int(length) != len(rest) {
		return nil, fmt.Errorf(
			"frame: original length mismatch: header says %d, got %d bytes",
			length, len(rest),
		)
	}

	payload := make([]byte, length)
	copy(payload, rest)

	return payload, nil
}
