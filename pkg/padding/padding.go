// Package padding implements Ghost Protocol's traffic-block padding:
// disguising the true size of a data payload by rounding it up to one of
// a small set of fixed block sizes with random filler bytes, per the spec
// ("Selects block sizes from [512, 1024, 1460] bytes ... Length metadata
// embedded inside the encrypted frame allows clean unpadding").
//
// Design note on where padding sits in the pipeline: it must pad the
// PLAINTEXT envelope before AEAD sealing, not the ciphertext after. AEAD's
// Open requires the exact ciphertext+tag bytes it was given by Seal -
// appending bytes after sealing does not "pad the ciphertext", it just
// corrupts it and Open will reject it. Padding the plaintext instead means
// the padding rides along as authenticated data inside the ciphertext, and
// frame.WriteFrame's on-wire Length field reports the padded (obfuscated)
// size rather than the real one - which is the actual point of this
// module. Pipeline: EncodePayload -> Pad -> Seal -> WriteFrame (send) /
// ReadFrame -> Open -> Unpad -> DecodePayload (receive).
//
// Unpad relies on pkg/frame's envelope format (a 2-byte big-endian length
// prefix, per EncodePayload/DecodePayload) to know where real data ends
// and padding begins - frame.DecodePayload itself requires an exact
// length match with no trailing bytes, so padding must be stripped before
// handing the envelope to DecodePayload.
package padding

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// BlockSizes are the fixed padding-target sizes, per spec, in ascending
// order. Callers should treat this as read-only.
var BlockSizes = []int{512, 1024, 1460}

// ErrEnvelopeTooLarge means the envelope (plus AEAD overhead) exceeds the
// largest available block size, so no padding target can hide it.
var ErrEnvelopeTooLarge = errors.New("padding: envelope too large for any configured block size")

// ErrEnvelopeTooShort means a padded envelope is too short to contain a
// valid 2-byte length prefix, and cannot be unpadded safely.
var ErrEnvelopeTooShort = errors.New("padding: padded envelope shorter than length prefix")

// ErrLengthPrefixInvalid means a padded envelope's embedded length prefix
// claims more real data than the envelope actually contains - never
// trust it blindly, since these bytes come off the wire (see Unpad).
var ErrLengthPrefixInvalid = errors.New("padding: length prefix exceeds envelope size")

// SelectBlockSize returns the smallest configured block size that can
// hold a plaintext of dataLen bytes once aeadOverhead (e.g. AEAD.Overhead(),
// the Poly1305 tag size) is added on top - i.e. the smallest B such that
// B - aeadOverhead >= dataLen, so the resulting ciphertext lands exactly
// at B bytes on the wire.
func SelectBlockSize(dataLen, aeadOverhead int) (int, error) {
	for _, b := range BlockSizes {
		if b-aeadOverhead >= dataLen {
			return b, nil
		}
	}
	return 0, fmt.Errorf(
		"%w: %d bytes (largest usable capacity is %d bytes with %d-byte AEAD overhead)",
		ErrEnvelopeTooLarge, dataLen, BlockSizes[len(BlockSizes)-1]-aeadOverhead, aeadOverhead,
	)
}

// Pad selects the smallest block size that fits envelope (a plaintext
// envelope from frame.EncodePayload) once aeadOverhead is accounted for,
// and appends cryptographically random filler bytes to reach it. The
// original envelope, including its own embedded length prefix, is
// preserved unchanged as a prefix of the returned slice - Unpad uses that
// prefix to recover it.
func Pad(envelope []byte, aeadOverhead int) ([]byte, error) {
	blockSize, err := SelectBlockSize(len(envelope), aeadOverhead)
	if err != nil {
		return nil, err
	}

	targetLen := blockSize - aeadOverhead
	fillerLen := targetLen - len(envelope)

	padded := make([]byte, targetLen)
	copy(padded, envelope)

	if fillerLen > 0 {
		if _, err := rand.Read(padded[len(envelope):]); err != nil {
			return nil, fmt.Errorf("padding: failed to generate random filler: %w", err)
		}
	}

	return padded, nil
}

// Unpad reverses Pad: given a padded plaintext envelope (the output of
// AEAD.Open on a previously-padded, sealed frame), it reads the envelope's
// own 2-byte length prefix - the same one frame.EncodePayload writes - and
// truncates away the random filler, returning exactly the original
// envelope bytes frame.DecodePayload expects.
//
// The length prefix is read from data that just came off the wire (post-
// decryption, but still attacker-influenced if the AEAD tag were somehow
// forged - which it should never be by the time this runs). Unpad
// validates the prefix against the envelope's actual size rather than
// trusting it blindly, so a corrupted prefix fails safely instead of
// slicing out of bounds.
func Unpad(padded []byte) ([]byte, error) {
	const lengthPrefixSize = 2

	if len(padded) < lengthPrefixSize {
		return nil, ErrEnvelopeTooShort
	}

	originalDataLen := int(binary.BigEndian.Uint16(padded[:lengthPrefixSize]))
	realEnvelopeLen := lengthPrefixSize + originalDataLen

	if realEnvelopeLen > len(padded) {
		return nil, fmt.Errorf(
			"%w: prefix claims %d bytes, envelope is only %d bytes",
			ErrLengthPrefixInvalid, realEnvelopeLen, len(padded),
		)
	}

	envelope := make([]byte, realEnvelopeLen)
	copy(envelope, padded[:realEnvelopeLen])
	return envelope, nil
}
