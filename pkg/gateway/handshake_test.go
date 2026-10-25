package gateway

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/yedukrishna012/ghost-proxy/pkg/crypto"
	"github.com/yedukrishna012/ghost-proxy/pkg/frame"
)

var (
	hsPSK      = bytes.Repeat([]byte{0x11}, 32)
	hsExporter = bytes.Repeat([]byte{0x42}, 32)
)

// hsStartServer runs Authenticate on one end of a pipe and returns the
// client end plus a channel that receives the server's result.
func hsStartServer(t *testing.T, psk, exporter []byte) (net.Conn, <-chan error) {
	t.Helper()
	s, err := NewAuthSession(psk, exporter)
	if err != nil {
		t.Fatalf("NewAuthSession: %v", err)
	}
	srv, cli := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- s.Authenticate(srv)
		srv.Close()
	}()
	t.Cleanup(func() { cli.Close() })
	return cli, done
}

// hsReadChallenge reads and checks the server's challenge frame.
func hsReadChallenge(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	f, err := frame.ReadFrame(conn)
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if f.Type != frame.TypeAuthChallenge {
		t.Fatalf("got frame type 0x%02x, want challenge", f.Type)
	}
	if len(f.Ciphertext) != crypto.ChallengeSize {
		t.Fatalf("challenge length %d, want %d", len(f.Ciphertext), crypto.ChallengeSize)
	}
	return f.Ciphertext
}

// hsSendResponse plays the client: HMAC the challenge, AEAD-seal it, and
// send it in a frame of the given type.
func hsSendResponse(t *testing.T, conn net.Conn, psk, exporter, challenge []byte, typ byte) {
	t.Helper()
	dataKey, authKey, err := crypto.DeriveSessionKeys(psk, exporter)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	resp, err := crypto.ComputeResponse(authKey, challenge)
	if err != nil {
		t.Fatalf("compute response: %v", err)
	}
	aead, err := crypto.NewAEAD(dataKey)
	if err != nil {
		t.Fatalf("new aead: %v", err)
	}
	nc, err := frame.NewNonceCounter()
	if err != nil {
		t.Fatalf("nonce counter: %v", err)
	}
	nonce := nc.Next()
	ct, err := aead.Seal(nonce[:], resp, []byte{typ})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := frame.WriteFrame(conn, &frame.Frame{Type: typ, Nonce: nonce, Ciphertext: ct}); err != nil {
		t.Fatalf("write response: %v", err)
	}
}

func hsWait(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("Authenticate did not return in time")
		return nil
	}
}

func TestHandshakeValid(t *testing.T) {
	cli, done := hsStartServer(t, hsPSK, hsExporter)
	ch := hsReadChallenge(t, cli)
	hsSendResponse(t, cli, hsPSK, hsExporter, ch, frame.TypeAuthResponse)
	ack, err := frame.ReadFrame(cli)
	if err != nil {
		t.Fatalf("read auth success: %v", err)
	}
	if ack.Type != frame.TypeAuthSuccess {
		t.Fatalf("got frame type 0x%02x, want auth success", ack.Type)
	}
	if err := hsWait(t, done); err != nil {
		t.Fatalf("valid client rejected: %v", err)
	}
}

func TestHandshakeWrongPSK(t *testing.T) {
	cli, done := hsStartServer(t, hsPSK, hsExporter)
	ch := hsReadChallenge(t, cli)
	badPSK := bytes.Repeat([]byte{0x99}, 32)
	hsSendResponse(t, cli, badPSK, hsExporter, ch, frame.TypeAuthResponse)
	if err := hsWait(t, done); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("got %v, want ErrAuthFailed", err)
	}
}

func TestHandshakeWrongExporter(t *testing.T) {
	cli, done := hsStartServer(t, hsPSK, hsExporter)
	ch := hsReadChallenge(t, cli)
	badExp := bytes.Repeat([]byte{0x07}, 32)
	hsSendResponse(t, cli, hsPSK, badExp, ch, frame.TypeAuthResponse)
	if err := hsWait(t, done); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("got %v, want ErrAuthFailed", err)
	}
}

func TestHandshakeWrongFrameType(t *testing.T) {
	cli, done := hsStartServer(t, hsPSK, hsExporter)
	ch := hsReadChallenge(t, cli)
	hsSendResponse(t, cli, hsPSK, hsExporter, ch, frame.TypeDataPayload)
	if err := hsWait(t, done); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("got %v, want ErrAuthFailed", err)
	}
}

func TestHandshakeReplayedResponseFails(t *testing.T) {
	// A response computed for a different challenge must not verify.
	cli, done := hsStartServer(t, hsPSK, hsExporter)
	_ = hsReadChallenge(t, cli)
	stale := bytes.Repeat([]byte{0xAA}, crypto.ChallengeSize)
	hsSendResponse(t, cli, hsPSK, hsExporter, stale, frame.TypeAuthResponse)
	if err := hsWait(t, done); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("got %v, want ErrAuthFailed", err)
	}
}

func TestHandshakeClientClosesEarly(t *testing.T) {
	cli, done := hsStartServer(t, hsPSK, hsExporter)
	_ = hsReadChallenge(t, cli)
	cli.Close()
	if err := hsWait(t, done); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("got %v, want ErrAuthFailed", err)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	old := authTimeout
	authTimeout = 100 * time.Millisecond
	t.Cleanup(func() { authTimeout = old })

	cli, done := hsStartServer(t, hsPSK, hsExporter)
	_ = hsReadChallenge(t, cli) // then stay silent
	if err := hsWait(t, done); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("got %v, want ErrAuthFailed", err)
	}
}
