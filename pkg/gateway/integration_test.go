// Package gateway_test contains cross-package integration tests for the
// Ghost Proxy authentication and framing pipeline. These are deliberately
// black-box (external test package, importing only exported APIs) because
// their purpose is to catch problems that live in the SEAMS between
// pkg/crypto, pkg/frame, and pkg/gateway - problems that each package's own
// unit tests, and gateway's own handshake_test.go/server_test.go/auth_test.go,
// structurally cannot see because they only exercise one layer at a time.
//
// This is the Day 3 "crypto integration tests" deliverable (owner map:
// Member D). Tests already covered by Yedu's handshake_test.go (valid
// handshake, wrong PSK, wrong frame type, timeout) are intentionally NOT
// duplicated here. Everything below exercises something none of the
// existing per-file test suites do.
package gateway_test

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/yedukrishna012/ghost-proxy/pkg/crypto"
	"github.com/yedukrishna012/ghost-proxy/pkg/frame"
	"github.com/yedukrishna012/ghost-proxy/pkg/gateway"
)

// newPipe returns a connected pair of in-memory net.Conns and registers cleanup.
func newPipe(t *testing.T) (serverConn, clientConn net.Conn) {
	t.Helper()
	serverConn, clientConn = net.Pipe()
	t.Cleanup(func() {
		serverConn.Close()
		clientConn.Close()
	})
	return serverConn, clientConn
}

// clientHandshake performs the CLIENT side of the authentication handshake
// over conn, mirroring the wire sequence documented in
// pkg/gateway/handshake.go. tamper, if non-nil, is applied to the outgoing
// response frame immediately before it is written, so individual tests can
// corrupt exactly one field of an otherwise-correct handshake.
func clientHandshake(t *testing.T, conn net.Conn, psk, exporter []byte, tamper func(f *frame.Frame)) error {
	t.Helper()

	dataKey, authKey, err := crypto.DeriveSessionKeys(psk, exporter)
	if err != nil {
		return err
	}

	challengeFrame, err := frame.ReadFrame(conn)
	if err != nil {
		return err
	}
	if challengeFrame.Type != frame.TypeAuthChallenge {
		t.Fatalf("expected TypeAuthChallenge (0x%02x), got 0x%02x", frame.TypeAuthChallenge, challengeFrame.Type)
	}
	challenge := challengeFrame.Ciphertext // sent in cleartext by design, per handshake.go

	response, err := crypto.ComputeResponse(authKey, challenge)
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

	out := &frame.Frame{
		Type:       frame.TypeAuthResponse,
		Nonce:      nonce,
		Ciphertext: sealed,
	}

	if tamper != nil {
		tamper(out)
	}

	if err := frame.WriteFrame(conn, out); err != nil {
		return err
	}

	if tamper == nil {
		ack, err := frame.ReadFrame(conn)
		if err != nil {
			return err
		}
		if ack.Type != frame.TypeAuthSuccess {
			t.Fatalf("expected TypeAuthSuccess (0x%02x), got 0x%02x", frame.TypeAuthSuccess, ack.Type)
		}
	}

	return nil
}

// --- Handshake tamper-detection tests not covered elsewhere -----------------

func TestIntegration_FullHandshake_TamperedCiphertext_Fails(t *testing.T) {
	psk := []byte("shared-psk")
	exporter := []byte("exporter-material")

	serverConn, clientConn := newPipe(t)
	session, err := gateway.NewAuthSession(psk, exporter)
	if err != nil {
		t.Fatalf("NewAuthSession returned error: %v", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- session.Authenticate(serverConn) }()

	tamper := func(f *frame.Frame) { f.Ciphertext[0] ^= 0xFF }
	if err := clientHandshake(t, clientConn, psk, exporter, tamper); err != nil {
		t.Fatalf("unexpected client-side error: %v", err)
	}

	if err := <-errCh; !errors.Is(err, gateway.ErrAuthFailed) {
		t.Errorf("expected ErrAuthFailed for tampered ciphertext, got: %v", err)
	}
}

func TestIntegration_FullHandshake_TamperedNonce_Fails(t *testing.T) {
	psk := []byte("shared-psk")
	exporter := []byte("exporter-material")

	serverConn, clientConn := newPipe(t)
	session, err := gateway.NewAuthSession(psk, exporter)
	if err != nil {
		t.Fatalf("NewAuthSession returned error: %v", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- session.Authenticate(serverConn) }()

	tamper := func(f *frame.Frame) { f.Nonce[0] ^= 0xFF }
	if err := clientHandshake(t, clientConn, psk, exporter, tamper); err != nil {
		t.Fatalf("unexpected client-side error: %v", err)
	}

	if err := <-errCh; !errors.Is(err, gateway.ErrAuthFailed) {
		t.Errorf("expected ErrAuthFailed for tampered nonce, got: %v", err)
	}
}

// TestIntegration_FullHandshake_TypeConfusion_Fails is a genuine cross-package
// finding: it seals a valid response under TypeDataPayload's AAD, but labels
// the wire frame's header as TypeAuthResponse. Neither pkg/crypto's tests
// (which never see a frame header) nor pkg/frame's tests (which never touch
// AEAD) can exercise this seam - only an integration test that drives both
// together can. handshake.go binds AEAD's additionalData to the frame's own
// Type byte (aead.Open(..., []byte{f.Type})), so header and AAD must agree;
// this test confirms a disagreement is correctly rejected.
func TestIntegration_FullHandshake_TypeConfusion_Fails(t *testing.T) {
	psk := []byte("shared-psk")
	exporter := []byte("exporter-material")

	serverConn, clientConn := newPipe(t)
	session, err := gateway.NewAuthSession(psk, exporter)
	if err != nil {
		t.Fatalf("NewAuthSession returned error: %v", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- session.Authenticate(serverConn) }()

	dataKey, authKey, err := crypto.DeriveSessionKeys(psk, exporter)
	if err != nil {
		t.Fatalf("DeriveSessionKeys returned error: %v", err)
	}

	challengeFrame, err := frame.ReadFrame(clientConn)
	if err != nil {
		t.Fatalf("ReadFrame (challenge) returned error: %v", err)
	}

	response, err := crypto.ComputeResponse(authKey, challengeFrame.Ciphertext)
	if err != nil {
		t.Fatalf("ComputeResponse returned error: %v", err)
	}

	aead, err := crypto.NewAEAD(dataKey)
	if err != nil {
		t.Fatalf("NewAEAD returned error: %v", err)
	}

	nc, err := frame.NewNonceCounter()
	if err != nil {
		t.Fatalf("NewNonceCounter returned error: %v", err)
	}
	nonce := nc.Next()

	// Seal under the WRONG type's AAD ...
	sealed, err := aead.Seal(nonce[:], response, []byte{frame.TypeDataPayload})
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	// ... but relabel the frame header as TypeAuthResponse before sending.
	if err := frame.WriteFrame(clientConn, &frame.Frame{
		Type:       frame.TypeAuthResponse,
		Nonce:      nonce,
		Ciphertext: sealed,
	}); err != nil {
		t.Fatalf("WriteFrame returned error: %v", err)
	}

	if err := <-errCh; !errors.Is(err, gateway.ErrAuthFailed) {
		t.Errorf("expected ErrAuthFailed for type-confused frame, got: %v", err)
	}
}

// TestIntegration_CapturedResponseReplayAcrossSessions_Fails is distinct from
// gateway's own TestHandshakeReplayedResponseFails: that test sends a
// response computed for an arbitrary WRONG challenge value within a single
// handshake attempt. This test runs two REAL, independently-completed
// handshake attempts against the same PSK/exporter pair, captures the exact
// wire bytes of a genuinely valid response frame from the first, and replays
// those captured bytes verbatim against the second handshake's fresh
// challenge - a truer simulation of an attacker recording and replaying
// real traffic, and a property that only shows up across two full session
// lifecycles, not within one.
func TestIntegration_CapturedResponseReplayAcrossSessions_Fails(t *testing.T) {
	psk := []byte("shared-psk")
	exporter := []byte("exporter-material")

	// --- First, successful handshake; capture the valid response frame. ---
	serverConn1, clientConn1 := newPipe(t)
	session1, err := gateway.NewAuthSession(psk, exporter)
	if err != nil {
		t.Fatalf("NewAuthSession returned error: %v", err)
	}

	errCh1 := make(chan error, 1)
	go func() { errCh1 <- session1.Authenticate(serverConn1) }()

	dataKey, authKey, err := crypto.DeriveSessionKeys(psk, exporter)
	if err != nil {
		t.Fatalf("DeriveSessionKeys returned error: %v", err)
	}

	challengeFrame1, err := frame.ReadFrame(clientConn1)
	if err != nil {
		t.Fatalf("ReadFrame (challenge 1) returned error: %v", err)
	}

	response1, err := crypto.ComputeResponse(authKey, challengeFrame1.Ciphertext)
	if err != nil {
		t.Fatalf("ComputeResponse returned error: %v", err)
	}

	aead, err := crypto.NewAEAD(dataKey)
	if err != nil {
		t.Fatalf("NewAEAD returned error: %v", err)
	}

	nc, err := frame.NewNonceCounter()
	if err != nil {
		t.Fatalf("NewNonceCounter returned error: %v", err)
	}
	nonce1 := nc.Next()

	sealed1, err := aead.Seal(nonce1[:], response1, []byte{frame.TypeAuthResponse})
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	replayFrame := &frame.Frame{
		Type:       frame.TypeAuthResponse,
		Nonce:      nonce1,
		Ciphertext: sealed1,
	}

	if err := frame.WriteFrame(clientConn1, replayFrame); err != nil {
		t.Fatalf("WriteFrame returned error: %v", err)
	}
	if _, err := frame.ReadFrame(clientConn1); err != nil {
		t.Fatalf("read authentication success: %v", err)
	}
	if err := <-errCh1; err != nil {
		t.Fatalf("expected first handshake to succeed, got error: %v", err)
	}

	// --- Second handshake, same PSK/exporter -> same dataKey/authKey - but
	// the "attacker" replays the exact frame bytes from the first handshake
	// instead of answering the new challenge. ---
	serverConn2, clientConn2 := newPipe(t)
	session2, err := gateway.NewAuthSession(psk, exporter)
	if err != nil {
		t.Fatalf("NewAuthSession returned error: %v", err)
	}

	errCh2 := make(chan error, 1)
	go func() { errCh2 <- session2.Authenticate(serverConn2) }()

	if _, err := frame.ReadFrame(clientConn2); err != nil {
		t.Fatalf("ReadFrame (challenge 2) returned error: %v", err)
	}
	if err := frame.WriteFrame(clientConn2, replayFrame); err != nil {
		t.Fatalf("WriteFrame (replay) returned error: %v", err)
	}

	if err := <-errCh2; !errors.Is(err, gateway.ErrAuthFailed) {
		t.Errorf("expected ErrAuthFailed for a captured response replayed against a new challenge, got: %v", err)
	}
}

// --- Post-handshake data channel integration tests (not covered elsewhere) --

// TestIntegration_DataChannel_RoundTrip exercises the full tunnel-traffic
// pipeline a real connection would use after a successful handshake:
// EncodePayload -> Seal -> WriteFrame -> (wire) -> ReadFrame -> Open ->
// DecodePayload, using the same DataKey a real AuthSession would hand off.
// Nothing in the existing test suites exercises pkg/frame's payload envelope
// together with pkg/crypto's AEAD and a real AuthSession-derived key.
func TestIntegration_DataChannel_RoundTrip(t *testing.T) {
	psk := []byte("shared-psk")
	exporter := []byte("exporter-material")

	session, err := gateway.NewAuthSession(psk, exporter)
	if err != nil {
		t.Fatalf("NewAuthSession returned error: %v", err)
	}

	aead, err := crypto.NewAEAD(session.DataKey())
	if err != nil {
		t.Fatalf("NewAEAD returned error: %v", err)
	}
	nc, err := frame.NewNonceCounter()
	if err != nil {
		t.Fatalf("NewNonceCounter returned error: %v", err)
	}

	original := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	envelope, err := frame.EncodePayload(original)
	if err != nil {
		t.Fatalf("EncodePayload returned error: %v", err)
	}

	nonce := nc.Next()
	sealed, err := aead.Seal(nonce[:], envelope, []byte{frame.TypeDataPayload})
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	var wire bytes.Buffer
	if err := frame.WriteFrame(&wire, &frame.Frame{
		Type:       frame.TypeDataPayload,
		Nonce:      nonce,
		Ciphertext: sealed,
	}); err != nil {
		t.Fatalf("WriteFrame returned error: %v", err)
	}

	got, err := frame.ReadFrame(&wire)
	if err != nil {
		t.Fatalf("ReadFrame returned error: %v", err)
	}

	openedEnvelope, err := aead.Open(got.Nonce[:], got.Ciphertext, []byte{got.Type})
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	payload, err := frame.DecodePayload(openedEnvelope)
	if err != nil {
		t.Fatalf("DecodePayload returned error: %v", err)
	}

	if !bytes.Equal(payload, original) {
		t.Fatalf("round trip mismatch: got %q, want %q", payload, original)
	}
}

// TestIntegration_DataChannel_TamperedFrameOnWire_Fails corrupts a single
// byte of the fully-framed WIRE BYTES (i.e. after WriteFrame, simulating
// on-path corruption or DPI middlebox interference) and confirms the
// corruption is caught during decryption.
func TestIntegration_DataChannel_TamperedFrameOnWire_Fails(t *testing.T) {
	psk := []byte("shared-psk")
	exporter := []byte("exporter-material")

	session, err := gateway.NewAuthSession(psk, exporter)
	if err != nil {
		t.Fatalf("NewAuthSession returned error: %v", err)
	}
	aead, err := crypto.NewAEAD(session.DataKey())
	if err != nil {
		t.Fatalf("NewAEAD returned error: %v", err)
	}
	nc, err := frame.NewNonceCounter()
	if err != nil {
		t.Fatalf("NewNonceCounter returned error: %v", err)
	}

	envelope, err := frame.EncodePayload([]byte("sensitive tunnel traffic"))
	if err != nil {
		t.Fatalf("EncodePayload returned error: %v", err)
	}
	nonce := nc.Next()
	sealed, err := aead.Seal(nonce[:], envelope, []byte{frame.TypeDataPayload})
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	var wire bytes.Buffer
	if err := frame.WriteFrame(&wire, &frame.Frame{
		Type:       frame.TypeDataPayload,
		Nonce:      nonce,
		Ciphertext: sealed,
	}); err != nil {
		t.Fatalf("WriteFrame returned error: %v", err)
	}

	wireBytes := wire.Bytes()
	if len(wireBytes) <= frame.HeaderSize {
		t.Fatal("test setup error: wire frame unexpectedly has no ciphertext")
	}
	wireBytes[frame.HeaderSize] ^= 0xFF // flip one bit just past the header

	got, err := frame.ReadFrame(bytes.NewReader(wireBytes))
	if err != nil {
		t.Fatalf("ReadFrame returned unexpected error on a structurally valid (but tampered) frame: %v", err)
	}

	if _, err := aead.Open(got.Nonce[:], got.Ciphertext, []byte{got.Type}); err == nil {
		t.Fatal("expected AEAD authentication failure for a tampered wire frame, got nil error")
	}
}

// TestIntegration_MaxPayloadLenExceedsFrameCapacity_FailsSafely documents a
// real inconsistency between pkg/frame's two exported limits:
// MaxPayloadLen (65535) bounds EncodePayload, but by the time a payload of
// that size is wrapped in its 2-byte length envelope and then AEAD-sealed
// (adding a 16-byte Poly1305 tag), the resulting ciphertext exceeds
// MaxCiphertextLen (also 65535). So a payload EncodePayload happily accepts
// can still be rejected by WriteFrame.
//
// This is not a security bug - WriteFrame's own bounds check catches it
// BEFORE the 2-byte wire Length field could silently wrap - but it is a
// real usability/consistency gap worth flagging to whoever owns pkg/frame:
// callers relying on MaxPayloadLen as "the largest payload I can send" will
// hit a runtime error for sizes near that limit. This test pins down the
// actual usable ceiling for the current AEAD overhead.
func TestIntegration_MaxPayloadLenExceedsFrameCapacity_FailsSafely(t *testing.T) {
	psk := []byte("shared-psk")
	exporter := []byte("exporter-material")

	session, err := gateway.NewAuthSession(psk, exporter)
	if err != nil {
		t.Fatalf("NewAuthSession returned error: %v", err)
	}
	aead, err := crypto.NewAEAD(session.DataKey())
	if err != nil {
		t.Fatalf("NewAEAD returned error: %v", err)
	}
	nc, err := frame.NewNonceCounter()
	if err != nil {
		t.Fatalf("NewNonceCounter returned error: %v", err)
	}

	payload := make([]byte, frame.MaxPayloadLen)
	envelope, err := frame.EncodePayload(payload)
	if err != nil {
		t.Fatalf("EncodePayload unexpectedly rejected a MaxPayloadLen-sized payload: %v", err)
	}

	nonce := nc.Next()
	sealed, err := aead.Seal(nonce[:], envelope, []byte{frame.TypeDataPayload})
	if err != nil {
		t.Fatalf("Seal returned error: %v", err)
	}

	err = frame.WriteFrame(&bytes.Buffer{}, &frame.Frame{
		Type:       frame.TypeDataPayload,
		Nonce:      nonce,
		Ciphertext: sealed,
	})
	if err == nil {
		t.Fatal("expected WriteFrame to reject an over-capacity frame, got nil error " +
			"(a nil error here would mean the 2-byte Length field silently wrapped instead of failing safely)")
	}

	overhead := aead.Overhead()
	maxUsablePayload := frame.MaxCiphertextLen - 2 - overhead // 2 = envelope's own length prefix
	t.Logf("frame.MaxPayloadLen (%d) exceeds the actual usable capacity once envelope "+
		"and AEAD overhead are accounted for; true max payload with current overhead is %d bytes",
		frame.MaxPayloadLen, maxUsablePayload)
}
