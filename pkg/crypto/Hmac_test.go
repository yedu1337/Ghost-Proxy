package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateChallenge_CorrectSizeAndUniqueness(t *testing.T) {
	c1, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge returned error: %v", err)
	}
	if len(c1) != ChallengeSize {
		t.Errorf("challenge length = %d, want %d", len(c1), ChallengeSize)
	}

	c2, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge returned error: %v", err)
	}
	if bytes.Equal(c1, c2) {
		t.Error("two calls to GenerateChallenge produced identical output")
	}
}

func TestComputeResponse_Deterministic(t *testing.T) {
	authKey := []byte("test-auth-key-derived-from-psk!")
	challenge := bytes.Repeat([]byte{0x42}, ChallengeSize)

	r1, err := ComputeResponse(authKey, challenge)
	if err != nil {
		t.Fatalf("ComputeResponse returned error: %v", err)
	}
	r2, err := ComputeResponse(authKey, challenge)
	if err != nil {
		t.Fatalf("ComputeResponse returned error: %v", err)
	}
	if !bytes.Equal(r1, r2) {
		t.Error("ComputeResponse is not deterministic for identical inputs")
	}
}

func TestComputeResponse_DifferentChallengeDifferentResponse(t *testing.T) {
	authKey := []byte("test-auth-key-derived-from-psk!")
	c1 := bytes.Repeat([]byte{0x01}, ChallengeSize)
	c2 := bytes.Repeat([]byte{0x02}, ChallengeSize)

	r1, err := ComputeResponse(authKey, c1)
	if err != nil {
		t.Fatalf("ComputeResponse returned error: %v", err)
	}
	r2, err := ComputeResponse(authKey, c2)
	if err != nil {
		t.Fatalf("ComputeResponse returned error: %v", err)
	}
	if bytes.Equal(r1, r2) {
		t.Error("different challenges must produce different responses")
	}
}

func TestVerifyResponse_ValidResponse(t *testing.T) {
	authKey := []byte("test-auth-key-derived-from-psk!")
	challenge, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge returned error: %v", err)
	}

	response, err := ComputeResponse(authKey, challenge)
	if err != nil {
		t.Fatalf("ComputeResponse returned error: %v", err)
	}

	ok, err := VerifyResponse(authKey, challenge, response)
	if err != nil {
		t.Fatalf("VerifyResponse returned error: %v", err)
	}
	if !ok {
		t.Error("VerifyResponse rejected a valid response")
	}
}

func TestVerifyResponse_WrongAuthKey(t *testing.T) {
	challenge, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge returned error: %v", err)
	}
	response, err := ComputeResponse([]byte("correct-key"), challenge)
	if err != nil {
		t.Fatalf("ComputeResponse returned error: %v", err)
	}

	ok, err := VerifyResponse([]byte("wrong-key-entirely"), challenge, response)
	if err != nil {
		t.Fatalf("VerifyResponse returned error: %v", err)
	}
	if ok {
		t.Error("VerifyResponse accepted a response computed with the wrong auth key — this is the exact failure mode that would let an attacker without the PSK authenticate")
	}
}

func TestVerifyResponse_TamperedResponse(t *testing.T) {
	authKey := []byte("test-auth-key-derived-from-psk!")
	challenge, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge returned error: %v", err)
	}
	response, err := ComputeResponse(authKey, challenge)
	if err != nil {
		t.Fatalf("ComputeResponse returned error: %v", err)
	}

	tampered := make([]byte, len(response))
	copy(tampered, response)
	tampered[0] ^= 0x01

	ok, err := VerifyResponse(authKey, challenge, tampered)
	if err != nil {
		t.Fatalf("VerifyResponse returned error: %v", err)
	}
	if ok {
		t.Error("VerifyResponse accepted a tampered response")
	}
}

func TestComputeResponse_RejectsEmptyAuthKey(t *testing.T) {
	challenge := bytes.Repeat([]byte{0x00}, ChallengeSize)
	if _, err := ComputeResponse(nil, challenge); err == nil {
		t.Fatal("expected error for empty authKey")
	}
}

func TestComputeResponse_RejectsWrongChallengeSize(t *testing.T) {
	if _, err := ComputeResponse([]byte("key"), []byte("too-short")); err == nil {
		t.Fatal("expected error for undersized challenge")
	}
}
