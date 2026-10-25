// Package crypto implements Ghost Protocol's cryptographic primitives:
// HKDF session key derivation, ChaCha20-Poly1305 AEAD, and HMAC-SHA256
// challenge-response authentication.
package crypto

import (
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KeySize is the derived session key length in bytes, matching
// chacha20poly1305.KeySize (32 bytes).
const KeySize = 32

// Context labels (HKDF "info" parameter) keep keys derived for different
// purposes cryptographically separate even from the same input material.
const (
	InfoDataKey = "ghost-protocol/data-key/v1"
	InfoAuthKey = "ghost-protocol/auth-key/v1"
	InfoC2SKey  = "ghost-protocol/data-key/c2s/v1"
	InfoS2CKey  = "ghost-protocol/data-key/s2c/v1"
)

// DeriveKey runs HKDF-SHA256 over the given secret material, mixing in
// salt (e.g. TLS exporter material) and a context-specific info label,
// and returns a KeySize-byte key.
//
// secret is typically the PSK; salt is typically TLS exporter material
// pulled from the established TLS 1.3 session, binding the derived key
// to that specific connection.
func DeriveKey(secret, salt []byte, info string) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("crypto: secret must not be empty")
	}
	if info == "" {
		return nil, errors.New("crypto: info label must not be empty")
	}

	kdf := hkdf.New(sha256.New, secret, salt, []byte(info))

	key := make([]byte, KeySize)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, errors.New("crypto: HKDF expansion failed")
	}
	return key, nil
}

// DeriveSessionKeys derives both the data-encryption key and the
// authentication key from the same PSK + TLS exporter material in one
// call, keeping the two purposes cryptographically separated via
// distinct info labels.
func DeriveSessionKeys(psk, exporterMaterial []byte) (dataKey, authKey []byte, err error) {
	dataKey, err = DeriveKey(psk, exporterMaterial, InfoDataKey)
	if err != nil {
		return nil, nil, err
	}
	authKey, err = DeriveKey(psk, exporterMaterial, InfoAuthKey)
	if err != nil {
		return nil, nil, err
	}
	return dataKey, authKey, nil
}

// DeriveDirectionalKeys returns independent client-to-server and server-to-client keys.
func DeriveDirectionalKeys(psk, exporterMaterial []byte) (c2s, s2c, auth []byte, err error) {
	c2s, err = DeriveKey(psk, exporterMaterial, InfoC2SKey)
	if err != nil {
		return
	}
	s2c, err = DeriveKey(psk, exporterMaterial, InfoS2CKey)
	if err != nil {
		return
	}
	auth, err = DeriveKey(psk, exporterMaterial, InfoAuthKey)
	return
}
