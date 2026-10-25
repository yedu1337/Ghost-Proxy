package frame

import (
	"bytes"
	"testing"
)

func TestEncodeDecodePayloadRoundTrip(t *testing.T) {
	original := []byte("hello ghost proxy")

	envelope, err := EncodePayload(original)
	if err != nil {
		t.Fatalf("EncodePayload failed: %v", err)
	}

	decoded, err := DecodePayload(envelope)
	if err != nil {
		t.Fatalf("DecodePayload failed: %v", err)
	}

	if !bytes.Equal(decoded, original) {
		t.Errorf("payload mismatch: got %q, want %q", decoded, original)
	}
}

func TestEncodeDecodeEmptyPayload(t *testing.T) {
	envelope, err := EncodePayload(nil)
	if err != nil {
		t.Fatalf("EncodePayload failed: %v", err)
	}

	decoded, err := DecodePayload(envelope)
	if err != nil {
		t.Fatalf("DecodePayload failed: %v", err)
	}

	if len(decoded) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(decoded))
	}
}

func TestEncodePayloadTooLarge(t *testing.T) {
	_, err := EncodePayload(make([]byte, MaxPayloadLen+1))
	if err == nil {
		t.Fatal("expected error for oversized payload, got nil")
	}
}

func TestDecodePayloadTooShort(t *testing.T) {
	_, err := DecodePayload([]byte{0x00})
	if err == nil {
		t.Fatal("expected error for envelope shorter than length prefix, got nil")
	}
}

func TestDecodePayloadLengthMismatch(t *testing.T) {
	envelope := []byte{0x00, 0x0A, 'a', 'b', 'c'}

	_, err := DecodePayload(envelope)
	if err == nil {
		t.Fatal("expected error for length/payload mismatch, got nil")
	}
}
