package padding

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// buildEnvelope mimics frame.EncodePayload's format (2-byte big-endian
// length prefix + payload) without importing pkg/frame, keeping this
// package's tests independent of that package's own test suite.
func buildEnvelope(payload []byte) []byte {
	envelope := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(envelope[:2], uint16(len(payload)))
	copy(envelope[2:], payload)
	return envelope
}

const testAEADOverhead = 16 // ChaCha20-Poly1305's Poly1305 tag size

func TestSelectBlockSize_PicksSmallestFit(t *testing.T) {
	cases := []struct {
		dataLen  int
		overhead int
		want     int
	}{
		{dataLen: 10, overhead: testAEADOverhead, want: 512},
		{dataLen: 512 - testAEADOverhead, overhead: testAEADOverhead, want: 512}, // exact fit
		{dataLen: 512 - testAEADOverhead + 1, overhead: testAEADOverhead, want: 1024},
		{dataLen: 1024 - testAEADOverhead, overhead: testAEADOverhead, want: 1024},
		{dataLen: 1024 - testAEADOverhead + 1, overhead: testAEADOverhead, want: 1460},
		{dataLen: 1460 - testAEADOverhead, overhead: testAEADOverhead, want: 1460},
	}

	for _, c := range cases {
		got, err := SelectBlockSize(c.dataLen, c.overhead)
		if err != nil {
			t.Errorf("SelectBlockSize(%d, %d) returned error: %v", c.dataLen, c.overhead, err)
			continue
		}
		if got != c.want {
			t.Errorf("SelectBlockSize(%d, %d) = %d, want %d", c.dataLen, c.overhead, got, c.want)
		}
	}
}

func TestSelectBlockSize_TooLarge(t *testing.T) {
	tooLarge := 1460 - testAEADOverhead + 1
	if _, err := SelectBlockSize(tooLarge, testAEADOverhead); !errors.Is(err, ErrEnvelopeTooLarge) {
		t.Errorf("expected ErrEnvelopeTooLarge, got: %v", err)
	}
}

func TestPad_ProducesExactBlockCapacity(t *testing.T) {
	envelope := buildEnvelope([]byte("small payload"))

	padded, err := Pad(envelope, testAEADOverhead)
	if err != nil {
		t.Fatalf("Pad returned error: %v", err)
	}

	wantLen := 512 - testAEADOverhead // smallest block fits this small payload
	if len(padded) != wantLen {
		t.Errorf("padded length = %d, want %d (so ciphertext lands at exactly 512 bytes on the wire)", len(padded), wantLen)
	}

	// The original envelope must be an unmodified prefix.
	if !bytes.Equal(padded[:len(envelope)], envelope) {
		t.Error("Pad must preserve the original envelope bytes unchanged as a prefix")
	}
}

func TestPad_FillerIsNotAllZero(t *testing.T) {
	// Weak but useful smoke test: confirm Pad doesn't just zero-fill
	// (which would create an obvious, non-random statistical signature -
	// the exact thing padding exists to avoid).
	envelope := buildEnvelope([]byte("x"))

	padded, err := Pad(envelope, testAEADOverhead)
	if err != nil {
		t.Fatalf("Pad returned error: %v", err)
	}

	filler := padded[len(envelope):]
	allZero := true
	for _, b := range filler {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero && len(filler) > 0 {
		t.Error("padding filler is all zero bytes - expected cryptographically random filler")
	}
}

func TestPad_ExactFitNoFiller(t *testing.T) {
	// A payload sized to exactly fill the smallest block after overhead
	// should produce zero filler bytes, not round up to the next block.
	targetLen := 512 - testAEADOverhead
	envelope := make([]byte, targetLen)
	binary.BigEndian.PutUint16(envelope[:2], uint16(targetLen-2))

	padded, err := Pad(envelope, testAEADOverhead)
	if err != nil {
		t.Fatalf("Pad returned error: %v", err)
	}
	if len(padded) != targetLen {
		t.Errorf("padded length = %d, want %d (exact fit should not round up)", len(padded), targetLen)
	}
}

func TestPad_RejectsOversizedEnvelope(t *testing.T) {
	tooLarge := make([]byte, 1460-testAEADOverhead+1)
	if _, err := Pad(tooLarge, testAEADOverhead); !errors.Is(err, ErrEnvelopeTooLarge) {
		t.Errorf("expected ErrEnvelopeTooLarge, got: %v", err)
	}
}

func TestPadUnpad_RoundTrip(t *testing.T) {
	payloads := [][]byte{
		[]byte("a"),
		[]byte("the quick brown fox jumps over the lazy dog"),
		bytes.Repeat([]byte{0xAB}, 500),
		bytes.Repeat([]byte{0xCD}, 1000),
		{}, // empty payload
	}

	for _, payload := range payloads {
		envelope := buildEnvelope(payload)

		padded, err := Pad(envelope, testAEADOverhead)
		if err != nil {
			t.Fatalf("Pad(len=%d) returned error: %v", len(payload), err)
		}

		unpadded, err := Unpad(padded)
		if err != nil {
			t.Fatalf("Unpad(len=%d) returned error: %v", len(payload), err)
		}

		if !bytes.Equal(unpadded, envelope) {
			t.Errorf("round trip mismatch for payload len=%d: got %v, want %v", len(payload), unpadded, envelope)
		}
	}
}

func TestPadUnpad_DifferentSizesProduceDifferentPaddedLengths(t *testing.T) {
	// Sanity check that padding actually normalizes distinct real sizes
	// toward the same bucket where possible - the whole point of block
	// padding is that many different real lengths become indistinguishable.
	small := buildEnvelope([]byte("hi"))
	alsoSmall := buildEnvelope(bytes.Repeat([]byte{0x01}, 100))

	paddedSmall, err := Pad(small, testAEADOverhead)
	if err != nil {
		t.Fatalf("Pad returned error: %v", err)
	}
	paddedAlsoSmall, err := Pad(alsoSmall, testAEADOverhead)
	if err != nil {
		t.Fatalf("Pad returned error: %v", err)
	}

	if len(paddedSmall) != len(paddedAlsoSmall) {
		t.Errorf("expected both small payloads to land in the same block after padding: got %d and %d bytes",
			len(paddedSmall), len(paddedAlsoSmall))
	}
}

func TestUnpad_TooShort(t *testing.T) {
	if _, err := Unpad([]byte{0x00}); !errors.Is(err, ErrEnvelopeTooShort) {
		t.Errorf("expected ErrEnvelopeTooShort, got: %v", err)
	}
}

func TestUnpad_InvalidLengthPrefix(t *testing.T) {
	// Prefix claims 65535 bytes of data, but the envelope is only 10 bytes.
	bogus := make([]byte, 10)
	binary.BigEndian.PutUint16(bogus[:2], 65535)

	if _, err := Unpad(bogus); !errors.Is(err, ErrLengthPrefixInvalid) {
		t.Errorf("expected ErrLengthPrefixInvalid, got: %v", err)
	}
}

func TestUnpad_DoesNotPanicOnGarbageInput(t *testing.T) {
	// Defensive: Unpad processes attacker-reachable, post-decryption
	// bytes (see doc comment) - it must fail with an error, never panic,
	// regardless of what garbage it's handed.
	inputs := [][]byte{
		nil,
		{},
		{0xFF},
		{0xFF, 0xFF},
		bytes.Repeat([]byte{0xFF}, 4),
	}

	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Unpad(%v) panicked: %v", in, r)
				}
			}()
			_, _ = Unpad(in)
		}()
	}
}
