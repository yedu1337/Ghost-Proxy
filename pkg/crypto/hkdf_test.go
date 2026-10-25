package crypto

import "testing"

func TestDeriveKey_ConsistentOutput(t *testing.T) {
	psk := []byte("test-pre-shared-key-material")
	salt := []byte("test-tls-exporter-material")

	k1, err := DeriveKey(psk, salt, InfoDataKey)
	if err != nil {
		t.Fatalf("DeriveKey returned error: %v", err)
	}
	k2, err := DeriveKey(psk, salt, InfoDataKey)
	if err != nil {
		t.Fatalf("DeriveKey returned error: %v", err)
	}

	if len(k1) != KeySize {
		t.Errorf("key length = %d, want %d", len(k1), KeySize)
	}
	if string(k1) != string(k2) {
		t.Error("DeriveKey is not deterministic for identical inputs")
	}
}

func TestDeriveKey_DifferentInfoProducesDifferentKeys(t *testing.T) {
	psk := []byte("test-pre-shared-key-material")
	salt := []byte("test-tls-exporter-material")

	dataKey, err := DeriveKey(psk, salt, InfoDataKey)
	if err != nil {
		t.Fatalf("DeriveKey (data) returned error: %v", err)
	}
	authKey, err := DeriveKey(psk, salt, InfoAuthKey)
	if err != nil {
		t.Fatalf("DeriveKey (auth) returned error: %v", err)
	}

	if string(dataKey) == string(authKey) {
		t.Error("keys derived with different info labels must differ")
	}
}

func TestDeriveKey_DifferentSaltProducesDifferentKeys(t *testing.T) {
	psk := []byte("test-pre-shared-key-material")

	k1, err := DeriveKey(psk, []byte("salt-one"), InfoDataKey)
	if err != nil {
		t.Fatalf("DeriveKey returned error: %v", err)
	}
	k2, err := DeriveKey(psk, []byte("salt-two"), InfoDataKey)
	if err != nil {
		t.Fatalf("DeriveKey returned error: %v", err)
	}

	if string(k1) == string(k2) {
		t.Error("keys derived with different salt (exporter material) must differ — this is what binds the session key to a specific TLS connection")
	}
}

func TestDeriveKey_EmptySecret(t *testing.T) {
	if _, err := DeriveKey(nil, []byte("salt"), InfoDataKey); err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestDeriveKey_EmptyInfo(t *testing.T) {
	if _, err := DeriveKey([]byte("psk"), []byte("salt"), ""); err == nil {
		t.Fatal("expected error for empty info label")
	}
}

func TestDeriveSessionKeys(t *testing.T) {
	psk := []byte("test-pre-shared-key-material")
	salt := []byte("test-tls-exporter-material")

	dataKey, authKey, err := DeriveSessionKeys(psk, salt)
	if err != nil {
		t.Fatalf("DeriveSessionKeys returned error: %v", err)
	}
	if len(dataKey) != KeySize || len(authKey) != KeySize {
		t.Fatalf("expected both keys to be %d bytes", KeySize)
	}
	if string(dataKey) == string(authKey) {
		t.Error("data key and auth key must not collide")
	}
}
