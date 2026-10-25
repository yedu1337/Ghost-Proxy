package socks5

import (
	"net"
	"testing"
	"time"
)

func TestRelay(t *testing.T) {
	clientProxy, clientApp := net.Pipe()
	targetProxy, targetServer := net.Pipe()

	done := make(chan error, 1)

	go func() {
		done <- relay(clientProxy, targetProxy)
	}()

	go func() {
		if _, err := clientApp.Write([]byte("hello target")); err != nil {
			return
		}
	}()

	targetServer.SetReadDeadline(time.Now().Add(time.Second))

	buf := make([]byte, 64)
	n, err := targetServer.Read(buf)
	if err != nil {
		t.Fatalf("failed to read client data at target: %v", err)
	}

	if string(buf[:n]) != "hello target" {
		t.Fatalf("unexpected target data: %q", buf[:n])
	}

	go func() {
		_, _ = targetServer.Write([]byte("hello client"))
	}()

	clientApp.SetReadDeadline(time.Now().Add(time.Second))

	buf = make([]byte, 64)
	n, err = clientApp.Read(buf)
	if err != nil {
		t.Fatalf("failed to read target data at client: %v", err)
	}

	if string(buf[:n]) != "hello client" {
		t.Fatalf("unexpected client data: %q", buf[:n])
	}

	clientProxy.Close()
	clientApp.Close()
	targetProxy.Close()
	targetServer.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not terminate")
	}
}
