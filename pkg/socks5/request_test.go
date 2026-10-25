package socks5

import (
	"net"
	"testing"
)

func parseRequest(t *testing.T, requestBytes []byte) *Request {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	done := make(chan struct {
		request *Request
		err     error
	}, 1)

	go func() {
		request, err := readRequest(serverConn)
		done <- struct {
			request *Request
			err     error
		}{request, err}
	}()

	if _, err := clientConn.Write(requestBytes); err != nil {
		t.Fatalf("failed to write request: %v", err)
	}

	result := <-done

	if result.err != nil {
		t.Fatalf("readRequest failed: %v", result.err)
	}

	return result.request
}

func TestReadRequestDomain(t *testing.T) {
	request := parseRequest(t, []byte{
		0x05, // SOCKS5
		0x01, // CONNECT
		0x00, // reserved
		0x03, // domain
		0x0B, // length = 11
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0x01, 0xBB, // port 443
	})

	if request.Command != cmdConnect {
		t.Fatalf("unexpected command: got 0x%02x", request.Command)
	}

	if request.Address != "example.com:443" {
		t.Fatalf("unexpected address: got %q", request.Address)
	}
}

func TestReadRequestIPv4(t *testing.T) {
	request := parseRequest(t, []byte{
		0x05, // SOCKS5
		0x01, // CONNECT
		0x00, // reserved
		0x01, // IPv4
		192, 168, 1, 10,
		0x1F, 0x90, // port 8080
	})

	if request.Address != "192.168.1.10:8080" {
		t.Fatalf("unexpected address: got %q", request.Address)
	}
}

func TestReadRequestIPv6(t *testing.T) {
	request := parseRequest(t, []byte{
		0x05, // SOCKS5
		0x01, // CONNECT
		0x00, // reserved
		0x04, // IPv6
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1, // ::1
		0x00, 0x16, // port 22
	})

	if request.Address != "[::1]:22" {
		t.Fatalf("unexpected address: got %q", request.Address)
	}
}
