package gateway

import (
	"errors"
	"fmt"

	ghostcrypto "github.com/yedukrishna012/ghost-proxy/pkg/crypto"
)

// AuthSession contains the cryptographic state for one authenticated
// gateway connection.
//
// The PSK and TLS exporter material are supplied by the connection layer.
// TLS integration itself is intentionally kept outside this package.
type AuthSession struct {
	dataKey []byte
	c2sKey  []byte
	s2cKey  []byte
	authKey []byte
}

// NewAuthSession derives the per-session data and authentication keys
// from the shared PSK and TLS exporter material.
func NewAuthSession(psk, exporterMaterial []byte) (*AuthSession, error) {
	if len(psk) == 0 {
		return nil, errors.New("gateway: PSK must not be empty")
	}

	c2s, s2c, authKey, err := ghostcrypto.DeriveDirectionalKeys(psk, exporterMaterial)
	if err != nil {
		return nil, fmt.Errorf("gateway: derive session keys: %w", err)
	}
	legacyDataKey, _, err := ghostcrypto.DeriveSessionKeys(psk, exporterMaterial)
	if err != nil {
		return nil, fmt.Errorf("gateway: derive compatibility key: %w", err)
	}

	return &AuthSession{
		dataKey: legacyDataKey, c2sKey: c2s, s2cKey: s2c,
		authKey: authKey,
	}, nil
}

func (s *AuthSession) ClientToServerKey() []byte {
	if s == nil {
		return nil
	}
	return append([]byte(nil), s.c2sKey...)
}
func (s *AuthSession) ServerToClientKey() []byte {
	if s == nil {
		return nil
	}
	return append([]byte(nil), s.s2cKey...)
}

// DataKey returns the compatibility key used by the legacy test handshake.
//
// Deprecated: data tunnels use ClientToServerKey and ServerToClientKey.
func (s *AuthSession) DataKey() []byte {
	if s == nil {
		return nil
	}

	return append([]byte(nil), s.dataKey...)
}

// Challenge creates a fresh authentication challenge.
func (s *AuthSession) Challenge() ([]byte, error) {
	if s == nil {
		return nil, errors.New("gateway: nil authentication session")
	}

	return ghostcrypto.GenerateChallenge()
}

// VerifyResponse validates a client's HMAC challenge response.
func (s *AuthSession) VerifyResponse(challenge, response []byte) (bool, error) {
	if s == nil {
		return false, errors.New("gateway: nil authentication session")
	}

	return ghostcrypto.VerifyResponse(s.authKey, challenge, response)
}
