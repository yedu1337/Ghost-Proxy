package transport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestTLSConfigEnforcesTLS13(t *testing.T) {
	cfg := TLSConfig("localhost")

	if cfg.MinVersion != utls.VersionTLS13 {
		t.Fatalf("MinVersion = %d, want TLS 1.3", cfg.MinVersion)
	}

	if cfg.MaxVersion != utls.VersionTLS13 {
		t.Fatalf("MaxVersion = %d, want TLS 1.3", cfg.MaxVersion)
	}

	if cfg.ServerName != "localhost" {
		t.Fatalf("ServerName = %q, want localhost", cfg.ServerName)
	}

	if cfg.Renegotiation != utls.RenegotiateNever {
		t.Fatalf(
			"Renegotiation = %d, want RenegotiateNever",
			cfg.Renegotiation,
		)
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
		t.Fatalf("NextProtos = %v, want only http/1.1", cfg.NextProtos)
	}
}

func TestTLS13UTLSHandshake(t *testing.T) {
	cert, pool := testCertificate(t)

	serverConn, clientConn := net.Pipe()

	serverTLS := utls.Server(serverConn, &utls.Config{
		Certificates:  []utls.Certificate{cert},
		MinVersion:    utls.VersionTLS13,
		MaxVersion:    utls.VersionTLS13,
		Renegotiation: utls.RenegotiateNever,
	})

	clientTLS := utls.UClient(
		clientConn,
		&utls.Config{
			ServerName:         "localhost",
			RootCAs:            pool,
			MinVersion:         utls.VersionTLS13,
			MaxVersion:         utls.VersionTLS13,
			Renegotiation:      utls.RenegotiateNever,
			InsecureSkipVerify: false,
		},
		utls.HelloChrome_Auto,
	)

	serverErr := make(chan error, 1)

	go func() {
		serverErr <- serverTLS.Handshake()
	}()

	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake failed: %v", err)
	}

	clientState := clientTLS.ConnectionState()
	serverState := serverTLS.ConnectionState()

	if clientState.Version != utls.VersionTLS13 {
		t.Fatalf(
			"client negotiated TLS version %d, want TLS 1.3",
			clientState.Version,
		)
	}

	if serverState.Version != utls.VersionTLS13 {
		t.Fatalf(
			"server negotiated TLS version %d, want TLS 1.3",
			serverState.Version,
		)
	}

	if !clientState.HandshakeComplete {
		t.Fatal("client TLS handshake is not marked complete")
	}

	if !serverState.HandshakeComplete {
		t.Fatal("server TLS handshake is not marked complete")
	}

	clientTLS.Close()
	serverTLS.Close()
}

func TestTLSExporterMaterial(t *testing.T) {
	cert, pool := testCertificate(t)

	serverConn, clientConn := net.Pipe()

	serverTLS := utls.Server(serverConn, &utls.Config{
		Certificates:  []utls.Certificate{cert},
		MinVersion:    utls.VersionTLS13,
		MaxVersion:    utls.VersionTLS13,
		Renegotiation: utls.RenegotiateNever,
	})

	clientConfig := TLSConfig("localhost")
	clientConfig.RootCAs = pool

	serverErr := make(chan error, 1)

	go func() {
		serverErr <- serverTLS.Handshake()
	}()

	clientTLS, err := dialUTLS(clientConn, clientConfig)
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake failed: %v", err)
	}

	clientState := clientTLS.ConnectionState()
	serverState := serverTLS.ConnectionState()

	t.Logf(
		"client renegotiation = %v",
		clientConfig.Renegotiation,
	)
	t.Logf(
		"client TLS version = %d",
		clientState.Version,
	)
	t.Logf(
		"server TLS version = %d",
		serverState.Version,
	)
	t.Logf(
		"client handshake complete = %v",
		clientState.HandshakeComplete,
	)
	t.Logf(
		"server handshake complete = %v",
		serverState.HandshakeComplete,
	)

	if clientState.Version != utls.VersionTLS13 ||
		serverState.Version != utls.VersionTLS13 {
		t.Fatal("TLS exporter test requires TLS 1.3 on both sides")
	}

	clientExporter, err := ExportKeyingMaterial(clientTLS)
	if err != nil {
		t.Fatalf("client exporter failed: %v", err)
	}

	serverExporter, err := serverState.ExportKeyingMaterial(
		ExporterLabel,
		nil,
		ExporterLength,
	)
	if err != nil {
		t.Fatalf("server exporter failed: %v", err)
	}

	if string(clientExporter) != string(serverExporter) {
		t.Fatal("client and server TLS exporter material does not match")
	}

	if len(clientExporter) != ExporterLength {
		t.Fatalf(
			"exporter length = %d, want %d",
			len(clientExporter),
			ExporterLength,
		)
	}

	clientTLS.Close()
	serverTLS.Close()
}

func TestVerifyTLS13ConnectionRejectsNonUTLS(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	defer serverConn.Close()
	defer clientConn.Close()

	if err := VerifyTLS13Connection(clientConn); err == nil {
		t.Fatal("expected non-uTLS connection to be rejected")
	}
}

func testCertificate(t *testing.T) (utls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	cert, err := utls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("create TLS certificate: %v", err)
	}

	pool := x509.NewCertPool()

	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to add test certificate to pool")
	}

	return cert, pool
}
