package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

const ClientAuthContext = "ghost-protocol/client-first-auth/v1"

// ClientProof binds possession of the PSK to the TLS exporter-derived auth key.
func ClientProof(authKey []byte) ([]byte, error) {
	if len(authKey) == 0 {
		return nil, errors.New("crypto: authKey must not be empty")
	}
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte(ClientAuthContext))
	return mac.Sum(nil), nil
}

func VerifyClientProof(authKey, proof []byte) bool {
	expected, err := ClientProof(authKey)
	return err == nil && hmac.Equal(expected, proof)
}

// ChallengeSize is the length of the server's random challenge nonce,
// per spec ("32-byte random challenge nonce").
const ChallengeSize = 32

// GenerateChallenge produces a fresh random challenge nonce for the
// server to send to a connecting client at the start of the
// authentication lifecycle.
func GenerateChallenge() ([]byte, error) {
	challenge := make([]byte, ChallengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return nil, errors.New("crypto: failed to generate challenge")
	}
	return challenge, nil
}

// ComputeResponse computes HMAC-SHA256(authKey, challenge), the value
// the client returns to prove possession of the shared PSK-derived
// auth key without revealing it.
func ComputeResponse(authKey, challenge []byte) ([]byte, error) {
	if len(authKey) == 0 {
		return nil, errors.New("crypto: authKey must not be empty")
	}
	if len(challenge) != ChallengeSize {
		return nil, errors.New("crypto: challenge must be 32 bytes")
	}
	mac := hmac.New(sha256.New, authKey)
	mac.Write(challenge)
	return mac.Sum(nil), nil
}

// VerifyResponse checks a client's response against the expected
// HMAC-SHA256(authKey, challenge) using a constant-time comparison to
// avoid leaking timing information about how much of the response
// matched.
func VerifyResponse(authKey, challenge, response []byte) (bool, error) {
	expected, err := ComputeResponse(authKey, challenge)
	if err != nil {
		return false, err
	}
	return hmac.Equal(expected, response), nil
}
