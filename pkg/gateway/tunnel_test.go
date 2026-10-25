package gateway

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/yedukrishna012/ghost-proxy/pkg/transport"
)

func TestServeTunnelForwardsTraffic(t *testing.T) {
	destinationListener, err := net.Listen(
		"tcp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatalf("listen destination: %v", err)
	}
	defer destinationListener.Close()

	destinationDone := make(chan error, 1)

	go func() {
		conn, err := destinationListener.Accept()
		if err != nil {
			destinationDone <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)

		n, err := conn.Read(buf)
		if err != nil {
			destinationDone <- err
			return
		}

		if _, err := conn.Write(buf[:n]); err != nil {
			destinationDone <- err
			return
		}

		destinationDone <- nil
	}()

	key := make([]byte, 32)

	session, err := NewAuthSession(key, nil)
	if err != nil {
		t.Fatalf("NewAuthSession: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	tunnelDone := make(chan error, 1)

	go func() {
		tunnelDone <- serveTunnel(
			serverConn,
			session,
			func(target string) (net.Conn, error) { return net.DialTimeout("tcp", target, 2*time.Second) },
		)
	}()

	clientChannel, err := transport.NewDirectionalDataChannel(
		session.ClientToServerKey(), session.ServerToClientKey(), 1, 2,
	)
	if err != nil {
		t.Fatalf("NewDataChannel: %v", err)
	}

	target := destinationListener.Addr().String()

	if err := clientChannel.WriteConnectFrame(
		clientConn,
		target,
	); err != nil {
		t.Fatalf("WriteConnectFrame: %v", err)
	}

	message := []byte("hello through gateway")

	if err := clientChannel.WriteDataFrame(
		clientConn,
		message,
	); err != nil {
		t.Fatalf("WriteDataFrame: %v", err)
	}

	reply, err := clientChannel.ReadDataFrame(clientConn)
	if err != nil {
		t.Fatalf("ReadDataFrame: %v", err)
	}

	if string(reply) != string(message) {
		t.Fatalf(
			"reply mismatch: got %q want %q",
			reply,
			message,
		)
	}

	if err := clientConn.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}

	select {
	case err := <-destinationDone:
		if err != nil && err != io.EOF {
			t.Fatalf("destination: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for destination")
	}

	select {
	case <-tunnelDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for tunnel")
	}
}
