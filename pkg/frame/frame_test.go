package frame

import (
	"bytes"
	"testing"
)

type countingWriter struct {
	calls int
	bytes.Buffer
}

func (w *countingWriter) Write(p []byte) (int, error) { w.calls++; return w.Buffer.Write(p) }

func TestWriteFrameUsesSingleWrite(t *testing.T) {
	w := &countingWriter{}
	if err := WriteFrame(w, &Frame{Type: TypeDataPayload, Ciphertext: []byte{1, 2, 3}}); err != nil {
		t.Fatal(err)
	}
	if w.calls != 1 {
		t.Fatalf("WriteFrame made %d writes, want 1", w.calls)
	}
}

func TestWriteReadFrameRoundTrip(t *testing.T) {
	nc, err := NewNonceCounter()
	if err != nil {
		t.Fatalf("NewNonceCounter failed: %v", err)
	}

	original := &Frame{
		Type:       TypeDataPayload,
		Nonce:      nc.Next(),
		Ciphertext: []byte("pretend-this-is-sealed-ciphertext"),
	}

	var buf bytes.Buffer

	if err := WriteFrame(&buf, original); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	decoded, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if decoded.Type != original.Type {
		t.Errorf("type mismatch: got 0x%02x, want 0x%02x", decoded.Type, original.Type)
	}

	if decoded.Nonce != original.Nonce {
		t.Errorf("nonce mismatch: got %x, want %x", decoded.Nonce, original.Nonce)
	}

	if !bytes.Equal(decoded.Ciphertext, original.Ciphertext) {
		t.Errorf("ciphertext mismatch: got %x, want %x", decoded.Ciphertext, original.Ciphertext)
	}
}

func TestWriteReadFrameZeroLengthCiphertext(t *testing.T) {
	nc, err := NewNonceCounter()
	if err != nil {
		t.Fatalf("NewNonceCounter failed: %v", err)
	}

	original := &Frame{
		Type:  TypeConnClose,
		Nonce: nc.Next(),
	}

	var buf bytes.Buffer

	if err := WriteFrame(&buf, original); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	decoded, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if len(decoded.Ciphertext) != 0 {
		t.Errorf("expected empty ciphertext, got %d bytes", len(decoded.Ciphertext))
	}
}

func TestWriteFrameNil(t *testing.T) {
	var buf bytes.Buffer

	if err := WriteFrame(&buf, nil); err == nil {
		t.Fatal("expected error writing nil frame, got nil")
	}
}

func TestWriteFrameInvalidType(t *testing.T) {
	var buf bytes.Buffer

	f := &Frame{Type: 0x99}

	if err := WriteFrame(&buf, f); err == nil {
		t.Fatal("expected error for invalid frame type, got nil")
	}
}

func TestWriteFrameCiphertextTooLarge(t *testing.T) {
	var buf bytes.Buffer

	f := &Frame{
		Type:       TypeDataPayload,
		Ciphertext: make([]byte, MaxCiphertextLen+1),
	}

	if err := WriteFrame(&buf, f); err == nil {
		t.Fatal("expected error for oversized ciphertext, got nil")
	}
}

func TestReadFrameInvalidType(t *testing.T) {
	header := make([]byte, HeaderSize)
	header[0] = 0x99

	buf := bytes.NewReader(header)

	if _, err := ReadFrame(buf); err == nil {
		t.Fatal("expected error for invalid frame type, got nil")
	}
}

func TestReadFrameTruncatedHeader(t *testing.T) {
	buf := bytes.NewReader([]byte{TypeDataPayload, 0x00})

	if _, err := ReadFrame(buf); err == nil {
		t.Fatal("expected error for truncated header, got nil")
	}
}

func TestReadFrameTruncatedCiphertext(t *testing.T) {
	header := make([]byte, HeaderSize)
	header[0] = TypeDataPayload
	header[1], header[2] = 0x00, 0x10

	buf := bytes.NewReader(header)

	if _, err := ReadFrame(buf); err == nil {
		t.Fatal("expected error for truncated ciphertext, got nil")
	}
}

func TestIsValidType(t *testing.T) {
	valid := []byte{TypeAuthChallenge, TypeAuthResponse, TypeDataPayload, TypeConnOpen, TypeConnClose}

	for _, ty := range valid {
		if !IsValidType(ty) {
			t.Errorf("expected 0x%02x to be valid", ty)
		}
	}

	if IsValidType(0x00) {
		t.Error("expected 0x00 to be invalid")
	}

}
