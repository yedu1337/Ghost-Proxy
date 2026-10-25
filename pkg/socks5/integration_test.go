package socks5

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func startTestTarget(t *testing.T) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test target: %v", err)
	}

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)

		requestLine, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		fmt.Fprintf(
			conn,
			"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
		)

		_ = requestLine
	}()

	return listener
}

func TestFullSOCKS5Connection(t *testing.T) {
	target := startTestTarget(t)
	defer target.Close()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start proxy listener: %v", err)
	}
	defer proxyListener.Close()

	go func() {
		conn, err := proxyListener.Accept()
		if err != nil {
			return
		}

		defer conn.Close()

		if err := handleConnection(conn, func(address string) (net.Conn, error) {
			return net.Dial("tcp", address)
		}); err != nil {
			t.Errorf("handleConnection failed: %v", err)
		}
	}()

	client, err := net.DialTimeout(
		"tcp",
		proxyListener.Addr().String(),
		time.Second,
	)
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	defer client.Close()

	// SOCKS5 greeting.
	if _, err := client.Write([]byte{
		0x05,
		0x01,
		0x00,
	}); err != nil {
		t.Fatalf("failed to send greeting: %v", err)
	}

	greetingReply := make([]byte, 2)

	if _, err := io.ReadFull(client, greetingReply); err != nil {
		t.Fatalf("failed to read greeting reply: %v", err)
	}

	expectedGreeting := []byte{0x05, 0x00}

	for i := range expectedGreeting {
		if greetingReply[i] != expectedGreeting[i] {
			t.Fatalf(
				"unexpected greeting reply: got %v, want %v",
				greetingReply,
				expectedGreeting,
			)
		}
	}

	// SOCKS5 CONNECT request to the local test target.
	targetAddr := target.Addr().(*net.TCPAddr)
	ip := targetAddr.IP.To4()

	request := []byte{
		0x05, // SOCKS5
		0x01, // CONNECT
		0x00, // reserved
		0x01, // IPv4
		ip[0],
		ip[1],
		ip[2],
		ip[3],
		byte(targetAddr.Port >> 8),
		byte(targetAddr.Port),
	}

	if _, err := client.Write(request); err != nil {
		t.Fatalf("failed to send CONNECT request: %v", err)
	}

	reply := make([]byte, 10)

	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("failed to read CONNECT reply: %v", err)
	}

	if reply[0] != 0x05 {
		t.Fatalf("unexpected SOCKS version in reply: 0x%02x", reply[0])
	}

	if reply[1] != replySucceeded {
		t.Fatalf("CONNECT failed with reply code: 0x%02x", reply[1])
	}

	// Send an HTTP request through the proxy.
	_, err = client.Write([]byte(
		"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
	))
	if err != nil {
		t.Fatalf("failed to send HTTP request: %v", err)
	}

	client.SetReadDeadline(time.Now().Add(time.Second))

	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("failed to read HTTP response: %v", err)
	}

	if len(response) == 0 {
		t.Fatal("received empty HTTP response")
	}
}
