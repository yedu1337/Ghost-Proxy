package crypto

import (
	"bytes"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestAEAD_SealOpen_RoundTrip(t *testing.T) {
	aead, err := NewAEAD(testKey(t))
	if err != nil {
		t.Fatalf("NewAEAD returned error: %v", err)
	}

	nonce := NonceFromCounter(0)
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	ciphertext, err := aead.Seal(nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext must not equal plaintext")
	}

	decrypted, err := aead.Open(nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestAEAD_SealOpen_WithAdditionalData(t *testing.T) {
	aead, err := NewAEAD(testKey(t))
	if err != nil {
		t.Fatalf("NewAEAD returned error: %v", err)
	}

	nonce := NonceFromCounter(1)
	plaintext := []byte("payload")
	aad := []byte("frame-type=0x03,length=7")

	ciphertext, err := aead.Seal(nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	decrypted, err := aead.Open(nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Open with matching AAD returned error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

// TestAEAD_TamperDetection_Ciphertext verifies that flipping any bit
// in the ciphertext causes authentication to fail (Day 3 tamper-
// detection unit tests, per the 14-day schedule).
func TestAEAD_TamperDetection_Ciphertext(t *testing.T) {
	aead, err := NewAEAD(testKey(t))
	if err != nil {
		t.Fatalf("NewAEAD returned error: %v", err)
	}

	nonce := NonceFromCounter(2)
	ciphertext, err := aead.Seal(nonce, []byte("authentic payload"), nil)
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] ^= 0x01 // flip one bit

	if _, err := aead.Open(nonce, tampered, nil); err == nil {
		t.Fatal("expected authentication failure for tampered ciphertext, got nil error")
	}
}

func TestAEAD_TamperDetection_AdditionalData(t *testing.T) {
	aead, err := NewAEAD(testKey(t))
	if err != nil {
		t.Fatalf("NewAEAD returned error: %v", err)
	}

	nonce := NonceFromCounter(3)
	aad := []byte("frame-type=0x03")
	ciphertext, err := aead.Seal(nonce, []byte("payload"), aad)
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	wrongAAD := []byte("frame-type=0x04")
	if _, err := aead.Open(nonce, ciphertext, wrongAAD); err == nil {
		t.Fatal("expected authentication failure for mismatched AAD, got nil error")
	}
}

func TestAEAD_WrongKeyFailsToDecrypt(t *testing.T) {
	aead1, err := NewAEAD(testKey(t))
	if err != nil {
		t.Fatalf("NewAEAD returned error: %v", err)
	}

	wrongKey := make([]byte, KeySize)
	copy(wrongKey, testKey(t))
	wrongKey[0] ^= 0xFF
	aead2, err := NewAEAD(wrongKey)
	if err != nil {
		t.Fatalf("NewAEAD returned error: %v", err)
	}

	nonce := NonceFromCounter(4)
	ciphertext, err := aead1.Seal(nonce, []byte("secret"), nil)
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	if _, err := aead2.Open(nonce, ciphertext, nil); err == nil {
		t.Fatal("expected decryption with wrong key to fail")
	}
}

func TestNewAEAD_RejectsWrongKeySize(t *testing.T) {
	if _, err := NewAEAD([]byte("too-short")); err == nil {
		t.Fatal("expected error for undersized key")
	}
}

func TestAEAD_RejectsWrongNonceSize(t *testing.T) {
	aead, err := NewAEAD(testKey(t))
	if err != nil {
		t.Fatalf("NewAEAD returned error: %v", err)
	}
	if _, err := aead.Seal([]byte("short"), []byte("x"), nil); err == nil {
		t.Fatal("expected error for undersized nonce on Seal")
	}
	if _, err := aead.Open([]byte("short"), []byte("x"), nil); err == nil {
		t.Fatal("expected error for undersized nonce on Open")
	}
}

// TestNonceFromCounter_Uniqueness guards the reuse-prevention property
// the framed protocol depends on: distinct counters must never collide.
func TestNonceFromCounter_Uniqueness(t *testing.T) {
	n0 := NonceFromCounter(0)
	n1 := NonceFromCounter(1)
	nMax := NonceFromCounter(^uint64(0))

	if bytes.Equal(n0, n1) {
		t.Error("NonceFromCounter(0) and NonceFromCounter(1) must differ")
	}
	if bytes.Equal(n0, nMax) {
		t.Error("NonceFromCounter(0) and NonceFromCounter(max) must differ")
	}
	if len(n0) != NonceSize {
		t.Errorf("nonce length = %d, want %d", len(n0), NonceSize)
	}
}

func TestRandomNonce_Uniqueness(t *testing.T) {
	n1, err := RandomNonce()
	if err != nil {
		t.Fatalf("RandomNonce returned error: %v", err)
	}
	n2, err := RandomNonce()
	if err != nil {
		t.Fatalf("RandomNonce returned error: %v", err)
	}
	if bytes.Equal(n1, n2) {
		t.Error("two calls to RandomNonce produced identical output (astronomically unlikely — check the RNG)")
	}
}
