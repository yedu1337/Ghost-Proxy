package socks5

import (
	"net"
	"testing"
)

func TestConnectToTarget(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start target listener: %v", err)
	}
	defer targetListener.Close()

	accepted := make(chan struct{})

	go func() {
		conn, err := targetListener.Accept()
		if err == nil {
			conn.Close()
		}
		close(accepted)
	}()

	request := &Request{
		Command: cmdConnect,
		Address: targetListener.Addr().String(),
	}

	conn, err := connectToTarget(request, func(address string) (net.Conn, error) {
		return net.Dial("tcp", address)
	})
	if err != nil {
		t.Fatalf("connectToTarget failed: %v", err)
	}
	conn.Close()

	<-accepted
}
