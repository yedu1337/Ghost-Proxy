package socks5

import (
	"net"
	"testing"
	"time"
)

func TestServerAcceptsConnection(t *testing.T) {
	server := &Server{
		Addr: "127.0.0.1:0",
	}

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	done := make(chan struct{})

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("failed to accept connection: %v", err)
			close(done)
			return
		}

		conn.Close()
		close(done)
	}()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	conn.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server did not accept connection")
	}
}
