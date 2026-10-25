package socks5

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestHandleGreetingNoAuthentication(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	done := make(chan error, 1)

	go func() {
		done <- handleGreeting(serverConn)
		serverConn.Close()
	}()

	_, err := clientConn.Write([]byte{
		socks5Version,
		0x01,
		noAuthentication,
	})
	if err != nil {
		t.Fatalf("failed to send greeting: %v", err)
	}

	response := make([]byte, 2)

	if _, err := io.ReadFull(clientConn, response); err != nil {
		t.Fatalf("failed to read server response: %v", err)
	}

	expected := []byte{
		socks5Version,
		noAuthentication,
	}

	if string(response) != string(expected) {
		t.Fatalf("unexpected response: got %v, want %v", response, expected)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handleGreeting failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handshake timed out")
	}

	clientConn.Close()
}
