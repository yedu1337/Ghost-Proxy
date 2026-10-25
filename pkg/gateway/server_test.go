package gateway

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yedukrishna012/ghost-proxy/pkg/crypto"
	"github.com/yedukrishna012/ghost-proxy/pkg/frame"
)

// hsClientAuth plays a complete client over TCP. It returns errors
// instead of calling t.Fatal so it is safe to use from goroutines.
func hsClientAuth(addr string, psk, exporter []byte) error {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}

	_, authKey, err := crypto.DeriveSessionKeys(psk, exporter)
	if err != nil {
		return err
	}
	resp, err := crypto.ClientProof(authKey)
	if err != nil {
		return err
	}
	return frame.WriteFrame(conn, &frame.Frame{
		Type: frame.TypeAuthResponse, Ciphertext: resp,
	})
}

// startTestServer starts a Server on a loopback port. Each authenticated
// connection sends one value on the returned channel.
func startTestServer(t *testing.T) (addr string, authed <-chan struct{}) {
	t.Helper()
	ch := make(chan struct{}, 64)
	srv := &Server{
		PSK:      hsPSK,
		Exporter: func(net.Conn) ([]byte, error) { return hsExporter, nil },
		OnAuthenticated: func(c net.Conn, _ *AuthSession) {
			c.Close()
			ch <- struct{}{}
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go srv.Serve(ln)
	return ln.Addr().String(), ch
}

func TestServerAuthenticatesValidClient(t *testing.T) {
	addr, authed := startTestServer(t)
	if err := hsClientAuth(addr, hsPSK, hsExporter); err != nil {
		t.Fatalf("client: %v", err)
	}
	select {
	case <-authed:
	case <-time.After(2 * time.Second):
		t.Fatal("handler was not called for a valid client")
	}
}

func TestServerRejectsWrongPSK(t *testing.T) {
	addr, authed := startTestServer(t)
	bad := bytes.Repeat([]byte{0x99}, 32)
	if err := hsClientAuth(addr, bad, hsExporter); err != nil {
		t.Fatalf("client: %v", err)
	}
	select {
	case <-authed:
		t.Fatal("handler was called for a wrong PSK")
	case <-time.After(500 * time.Millisecond):
	}
}

func TestServerFallbackReplaysWrongPSKFrame(t *testing.T) {
	replayed := make(chan []byte, 1)
	srv := &Server{PSK: hsPSK, Exporter: func(net.Conn) ([]byte, error) { return hsExporter, nil }, OnFallback: func(c net.Conn, r io.Reader) {
		data := make([]byte, frame.HeaderSize+32)
		_, _ = io.ReadFull(r, data)
		replayed <- data
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nDecoy page")
		_ = c.Close()
	}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Repeat([]byte{0x99}, 32)
	_, auth, err := crypto.DeriveSessionKeys(bad, hsExporter)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := crypto.ClientProof(auth)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := frame.WriteFrame(&wire, &frame.Frame{Type: frame.TypeAuthResponse, Ciphertext: proof}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(wire.Bytes()); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(c)
	_ = c.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(response, []byte("Decoy page")) {
		t.Fatalf("decoy response missing: %q", response)
	}
	select {
	case got := <-replayed:
		if !bytes.Equal(got, wire.Bytes()) {
			t.Fatalf("fallback replay mismatch: %x != %x", got, wire.Bytes())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fallback did not receive frame")
	}
}

func TestServerConcurrentClients(t *testing.T) {
	addr, authed := startTestServer(t)
	const n = 20
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { errs <- hsClientAuth(addr, hsPSK, hsExporter) }()
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("client: %v", err)
		}
	}
	for i := 0; i < n; i++ {
		select {
		case <-authed:
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d of %d clients authenticated", i, n)
		}
	}
}

func TestHandshakeRunsOutsideAcceptLoop(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var n atomic.Int32
	srv := &Server{PSK: hsPSK, Prepare: func(c net.Conn) (net.Conn, error) {
		if n.Add(1) == 1 {
			started <- struct{}{}
			<-release
		} else {
			started <- struct{}{}
		}
		return c, nil
	}, Exporter: func(net.Conn) ([]byte, error) { return hsExporter, nil }, OnAuthenticated: func(c net.Conn, _ *AuthSession) { _ = c.Close() }}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	first, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	<-started
	secondErr := make(chan error, 1)
	go func() { secondErr <- hsClientAuth(ln.Addr().String(), hsPSK, hsExporter) }()
	select {
	case err := <-secondErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a slow TLS setup blocked the accept loop")
	}
	close(release)
}
