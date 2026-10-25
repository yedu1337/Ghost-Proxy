package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// NonceSize matches chacha20poly1305.NonceSize (12 bytes), per the
// framed protocol's wire format (Nonce field).
const NonceSize = chacha20poly1305.NonceSize

// AEAD wraps a ChaCha20-Poly1305 cipher instance bound to a single
// derived session key.
type AEAD struct {
	cipher cipherAEAD
}

// cipherAEAD is the subset of cipher.AEAD we rely on; kept as an
// interface to make the type testable/mockable if ever needed.
type cipherAEAD interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
	Overhead() int
}

// NewAEAD constructs an AEAD instance from a KeySize-byte session key
// (as produced by DeriveKey / DeriveSessionKeys).
func NewAEAD(key []byte) (*AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("crypto: key must be 32 bytes")
	}
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, errors.New("crypto: failed to initialize ChaCha20-Poly1305")
	}
	return &AEAD{cipher: c}, nil
}

// Seal encrypts and authenticates plaintext under the given nonce,
// returning ciphertext with the Poly1305 tag appended. additionalData
// may be nil; when present it is authenticated but not encrypted
// (e.g. frame type / length fields from the wire header).
//
// Nonce reuse under the same key completely breaks ChaCha20-Poly1305's
// confidentiality and integrity guarantees — callers MUST use
// NonceFromCounter (or an equivalent unique-per-frame scheme) and MUST
// NOT reuse a nonce with the same key.
func (a *AEAD) Seal(nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, errors.New("crypto: nonce must be 12 bytes")
	}
	return a.cipher.Seal(nil, nonce, plaintext, additionalData), nil
}

// Open decrypts and verifies ciphertext under the given nonce. It
// returns an error (without leaking which part of the check failed)
// if authentication fails — callers must treat any error here as
// "drop the frame / close the connection", never as a partial result.
func (a *AEAD) Open(nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, errors.New("crypto: nonce must be 12 bytes")
	}
	plaintext, err := a.cipher.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, errors.New("crypto: authentication failed")
	}
	return plaintext, nil
}

// Overhead returns the number of bytes added by Seal (the Poly1305 tag).
func (a *AEAD) Overhead() int {
	return a.cipher.Overhead()
}

// NonceFromCounter deterministically builds a 12-byte nonce from a
// monotonically increasing per-connection frame counter, as specified
// by the framed protocol ("unique 12-byte nonce per frame derived from
// incremental counters to prevent reuse attacks").
//
// The counter occupies the low 8 bytes (big-endian); the top 4 bytes
// are zero. Caller is responsible for ensuring the counter never
// repeats within the lifetime of a given key (e.g. reset only on
// rekey, never on retry of the same frame).
func NonceFromCounter(counter uint64) []byte {
	nonce := make([]byte, NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// RandomNonce generates a cryptographically random 12-byte nonce.
// Prefer NonceFromCounter for the data channel (per spec); RandomNonce
// is useful for one-off values such as the auth challenge nonce.
func RandomNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("crypto: failed to generate random nonce")
	}
	return nonce, nil
}
