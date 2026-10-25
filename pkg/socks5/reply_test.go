package socks5

import (
	"io"
	"net"
	"testing"
)

func TestSendReplySuccessIPv4(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	done := make(chan error, 1)

	go func() {
		addr := &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 8080,
		}

		done <- sendReply(serverConn, replySucceeded, addr)
	}()

	expected := []byte{
		0x05, // SOCKS5
		0x00, // success
		0x00, // reserved
		0x01, // IPv4
		127, 0, 0, 1,
		0x1F, 0x90, // 8080
	}

	actual := make([]byte, len(expected))

	if _, err := io.ReadFull(clientConn, actual); err != nil {
		t.Fatalf("failed to read reply: %v", err)
	}

	for i := range expected {
		if actual[i] != expected[i] {
			t.Fatalf(
				"unexpected reply at byte %d: got 0x%02x, want 0x%02x",
				i,
				actual[i],
				expected[i],
			)
		}
	}

	if err := <-done; err != nil {
		t.Fatalf("sendReply failed: %v", err)
	}
}
