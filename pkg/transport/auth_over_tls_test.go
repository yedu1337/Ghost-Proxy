// Day 4 deliverable (Member B): validate authentication pass-through over
// TLS. The existing pkg/gateway/integration_test.go tests
// gateway.NewAuthSession end-to-end against crypto/frame â€” but every one of
// those tests runs over net.Pipe(), an in-memory, unencrypted connection.
// Nothing in the existing suites proves the auth handshake survives being
// carried over an actual TLS 1.3 connection using the real Chrome-spoofed
// uTLS dialer (pkg/transport). This file closes that specific gap.
//
// Deliberately package transport (white-box), not transport_test: the
// exported DialUTLS always builds its own TLS config internally and offers
// no way to inject a trusted cert pool for a self-signed test certificate.
// The unexported dialUTLS does accept a custom *utls.Config â€” its own doc
// comment says this exists so tests can supply a trusted pool without
// disabling verification â€” so this test has to live in-package to reach it.
package transport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/yedukrishna012/ghost-proxy/pkg/crypto"
	"github.com/yedukrishna012/ghost-proxy/pkg/frame"
	"github.com/yedukrishna012/ghost-proxy/pkg/gateway"
)

// --- test fixture: self-signed cert for "localhost" -------------------------

// generateSelfSignedCert writes a fresh self-signed cert/key pair for
// "localhost" to temp files (what TLSServerConfig requires) and also
// returns the cert in PEM form so the client side can add it to a trusted
// pool, since it won't be in any real trust store.
func generateSelfSignedCert(t *testing.T) (certFile, keyFile string, certPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal test private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("failed to write test cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("failed to write test key file: %v", err)
	}

	return certFile, keyFile, certPEM
}

// dialClientForTest builds a uTLS client connection trusting only the
// supplied self-signed cert (real verification, not InsecureSkipVerify),
// exercising the same Chrome-spoofed ClientHello path DialUTLS uses.
func dialClientForTest(t *testing.T, rawConn net.Conn, certPEM []byte) *utls.UConn {
	t.Helper()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to add test cert to client trust pool")
	}

	cfg := TLSConfig("localhost")
	cfg.RootCAs = pool

	conn, err := dialUTLS(rawConn, cfg)
	if err != nil {
		t.Fatalf("dialUTLS returned error: %v", err)
	}
	return conn
}

// clientAuthHandshake performs the CLIENT side of pkg/gateway's auth
// handshake over an already-established connection (here, a real TLS
// connection instead of net.Pipe()), mirroring pkg/gateway/handshake.go's
// wire sequence. tamper, if non-nil, corrupts the outgoing response frame.
func clientAuthHandshake(conn net.Conn, psk, exporter []byte, tamper func(f *frame.Frame)) error {
	dataKey, authKey, err := crypto.DeriveSessionKeys(psk, exporter)
	if err != nil {
		return err
	}

	challengeFrame, err := frame.ReadFrame(conn)
	if err != nil {
		return err
	}
	if challengeFrame.Type != frame.TypeAuthChallenge {
		return errors.New("expected TypeAuthChallenge frame")
	}

	response, err := crypto.ComputeResponse(authKey, challengeFrame.Ciphertext)
	if err != nil {
		return err
	}

	aead, err := crypto.NewAEAD(dataKey)
	if err != nil {
		return err
	}
	nc, err := frame.NewNonceCounter()
	if err != nil {
		return err
	}
	nonce := nc.Next()

	sealed, err := aead.Seal(nonce[:], response, []byte{frame.TypeAuthResponse})
	if err != nil {
		return err
	}

	out := &frame.Frame{Type: frame.TypeAuthResponse, Nonce: nonce, Ciphertext: sealed}
	if tamper != nil {
		tamper(out)
	}
	return frame.WriteFrame(conn, out)
}

// --- the actual Day 4 tests --------------------------------------------------

// TestAuthOverRealTLS_Success proves the full stack works together: a real
// TCP listener, a real spoofed-Chrome TLS 1.3 handshake (client and server
// sides of pkg/transport), TLS exporter material pulled from that live
// session on both ends, and gateway.NewAuthSession's challenge/response
// running over the resulting *utls connection* â€” not net.Pipe().
func TestAuthOverRealTLS_Success(t *testing.T) {
	certFile, keyFile, certPEM := generateSelfSignedCert(t)
	psk := []byte("shared-psk-for-tls-integration-test")

	serverCfg, err := TLSServerConfig(certFile, keyFile)
	if err != nil {
		t.Fatalf("TLSServerConfig returned error: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	type serverResult struct {
		exporter []byte
		authErr  error
		err      error
	}
	serverCh := make(chan serverResult, 1)

	go func() {
		rawConn, err := ln.Accept()
		if err != nil {
			serverCh <- serverResult{err: err}
			return
		}
		defer rawConn.Close()

		tlsConn, err := TLSServer(rawConn, serverCfg)
		if err != nil {
			serverCh <- serverResult{err: err}
			return
		}

		exporter, err := ExportServerKeyingMaterial(tlsConn)
		if err != nil {
			serverCh <- serverResult{err: err}
			return
		}

		session, err := gateway.NewAuthSession(psk, exporter)
		if err != nil {
			serverCh <- serverResult{err: err}
			return
		}

		//lint:ignore SA1019 This test covers the deprecated server-first compatibility handshake.
		authErr := session.Authenticate(tlsConn)
		serverCh <- serverResult{exporter: exporter, authErr: authErr}
	}()

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial listener: %v", err)
	}
	defer rawConn.Close()

	clientTLS := dialClientForTest(t, rawConn, certPEM)
	defer clientTLS.Close()

	if err := VerifyTLS13Connection(clientTLS); err != nil {
		t.Fatalf("VerifyTLS13Connection returned error: %v", err)
	}

	clientExporter, err := ExportKeyingMaterial(clientTLS)
	if err != nil {
		t.Fatalf("ExportKeyingMaterial (client) returned error: %v", err)
	}

	if err := clientAuthHandshake(clientTLS, psk, clientExporter, nil); err != nil {
		t.Fatalf("client-side auth handshake failed: %v", err)
	}

	result := <-serverCh
	if result.err != nil {
		t.Fatalf("server-side setup failed: %v", result.err)
	}
	if result.authErr != nil {
		t.Fatalf("expected authentication to succeed over real TLS, got: %v", result.authErr)
	}

	// Cryptographic sanity check specific to this integration point: the
	// exporter material both sides independently pulled from the SAME TLS
	// session must be byte-identical, since it's what both derive their
	// session keys from. If this diverges, auth would fail for a much
	// stranger reason than a wrong PSK.
	if !bytes.Equal(result.exporter, clientExporter) {
		t.Fatal("server and client TLS exporter material diverged for the same session")
	}
}

// TestAuthOverRealTLS_WrongPSK_Fails confirms a mismatched PSK is still
// correctly rejected when the handshake is carried over a real TLS
// connection, not just over net.Pipe() as gateway's own tests cover.
func TestAuthOverRealTLS_WrongPSK_Fails(t *testing.T) {
	certFile, keyFile, certPEM := generateSelfSignedCert(t)
	serverPSK := []byte("server-side-psk")
	clientPSK := []byte("client-has-the-wrong-psk")

	serverCfg, err := TLSServerConfig(certFile, keyFile)
	if err != nil {
		t.Fatalf("TLSServerConfig returned error: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		rawConn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer rawConn.Close()

		tlsConn, err := TLSServer(rawConn, serverCfg)
		if err != nil {
			errCh <- err
			return
		}
		exporter, err := ExportServerKeyingMaterial(tlsConn)
		if err != nil {
			errCh <- err
			return
		}
		session, err := gateway.NewAuthSession(serverPSK, exporter)
		if err != nil {
			errCh <- err
			return
		}
		//lint:ignore SA1019 This test covers the deprecated server-first compatibility handshake.
		errCh <- session.Authenticate(tlsConn)
	}()

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial listener: %v", err)
	}
	defer rawConn.Close()

	clientTLS := dialClientForTest(t, rawConn, certPEM)
	defer clientTLS.Close()

	clientExporter, err := ExportKeyingMaterial(clientTLS)
	if err != nil {
		t.Fatalf("ExportKeyingMaterial (client) returned error: %v", err)
	}

	if err := clientAuthHandshake(clientTLS, clientPSK, clientExporter, nil); err != nil {
		t.Fatalf("unexpected client-side transport error: %v", err)
	}

	authErr := <-errCh
	if !errors.Is(authErr, gateway.ErrAuthFailed) {
		t.Errorf("expected gateway.ErrAuthFailed for mismatched PSK over real TLS, got: %v", authErr)
	}
}

func TestClientFirstWrongPSKReceivesDecoyOverTLS(t *testing.T) {
	certFile, keyFile, certPEM := generateSelfSignedCert(t)
	serverCfg, err := TLSServerConfig(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverPSK := []byte("right-key-for-real-tls-fallback")
	replayed := make(chan []byte, 1)
	srv := &gateway.Server{PSK: serverPSK, Prepare: func(c net.Conn) (net.Conn, error) {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		tlsConn, e := TLSServer(c, serverCfg)
		if e == nil {
			_ = tlsConn.SetDeadline(time.Time{})
		}
		return tlsConn, e
	}, Exporter: func(c net.Conn) ([]byte, error) {
		tlsConn, ok := c.(*utls.Conn)
		if !ok {
			return nil, errors.New("not a uTLS server connection")
		}
		return ExportServerKeyingMaterial(tlsConn)
	}, OnFallback: func(c net.Conn, r io.Reader) {
		b := make([]byte, frame.HeaderSize+32)
		_, _ = io.ReadFull(r, b)
		replayed <- b
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nDecoy page")
		_ = c.Close()
	}}
	go srv.Serve(ln)
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientTLS := dialClientForTest(t, raw, certPEM)
	defer clientTLS.Close()
	exporter, err := ExportKeyingMaterial(clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	_, authKey, err := crypto.DeriveSessionKeys([]byte("wrong-key-for-real-tls-fallback"), exporter)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := crypto.ClientProof(authKey)
	if err != nil {
		t.Fatal(err)
	}
	var sent bytes.Buffer
	if err := frame.WriteFrame(&sent, &frame.Frame{Type: frame.TypeAuthResponse, Ciphertext: proof}); err != nil {
		t.Fatal(err)
	}
	_ = clientTLS.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := clientTLS.Write(sent.Bytes()); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(response, []byte("Decoy page")) {
		t.Fatalf("decoy page missing: %q", response)
	}
	select {
	case got := <-replayed:
		if !bytes.Equal(got, sent.Bytes()) {
			t.Fatalf("fallback replay differs: %x != %x", got, sent.Bytes())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fallback did not receive consumed auth frame")
	}
}
