package gateway

import (
	"bytes"
	"testing"

	ghostcrypto "github.com/yedukrishna012/ghost-proxy/pkg/crypto"
)

func TestAuthSession_ChallengeResponse(t *testing.T) {
	psk := []byte("test-pre-shared-key-material")
	exporter := []byte("test-tls-exporter-material")

	server, err := NewAuthSession(psk, exporter)
	if err != nil {
		t.Fatalf("NewAuthSession returned error: %v", err)
	}

	clientDataKey, clientAuthKey, err := ghostcrypto.DeriveSessionKeys(psk, exporter)
	if err != nil {
		t.Fatalf("client key derivation failed: %v", err)
	}

	if len(clientDataKey) == 0 {
		t.Fatal("client data key is empty")
	}

	challenge, err := server.Challenge()
	if err != nil {
		t.Fatalf("Challenge returned error: %v", err)
	}

	response, err := ghostcrypto.ComputeResponse(clientAuthKey, challenge)
	if err != nil {
		t.Fatalf("ComputeResponse returned error: %v", err)
	}

	ok, err := server.VerifyResponse(challenge, response)
	if err != nil {
		t.Fatalf("VerifyResponse returned error: %v", err)
	}

	if !ok {
		t.Fatal("valid authentication response was rejected")
	}
}

func TestAuthSession_WrongPSKRejected(t *testing.T) {
	server, err := NewAuthSession(
		[]byte("correct-pre-shared-key"),
		[]byte("tls-exporter-material"),
	)
	if err != nil {
		t.Fatalf("server session: %v", err)
	}

	_, clientAuthKey, err := ghostcrypto.DeriveSessionKeys(
		[]byte("wrong-pre-shared-key"),
		[]byte("tls-exporter-material"),
	)
	if err != nil {
		t.Fatalf("client key derivation: %v", err)
	}

	challenge, err := server.Challenge()
	if err != nil {
		t.Fatalf("Challenge returned error: %v", err)
	}

	response, err := ghostcrypto.ComputeResponse(clientAuthKey, challenge)
	if err != nil {
		t.Fatalf("ComputeResponse returned error: %v", err)
	}

	ok, err := server.VerifyResponse(challenge, response)
	if err != nil {
		t.Fatalf("VerifyResponse returned error: %v", err)
	}

	if ok {
		t.Fatal("authentication succeeded with the wrong PSK")
	}
}

func TestAuthSession_DifferentExporterProducesDifferentKeys(t *testing.T) {
	psk := []byte("test-pre-shared-key")

	first, err := NewAuthSession(psk, []byte("exporter-one"))
	if err != nil {
		t.Fatalf("first session: %v", err)
	}

	second, err := NewAuthSession(psk, []byte("exporter-two"))
	if err != nil {
		t.Fatalf("second session: %v", err)
	}

	if bytes.Equal(first.DataKey(), second.DataKey()) {
		t.Fatal("different TLS exporter material produced the same data key")
	}

	if bytes.Equal(first.authKey, second.authKey) {
		t.Fatal("different TLS exporter material produced the same auth key")
	}
}

func TestAuthSession_EmptyPSKRejected(t *testing.T) {
	if _, err := NewAuthSession(nil, []byte("exporter")); err == nil {
		t.Fatal("expected empty PSK to be rejected")
	}
}
