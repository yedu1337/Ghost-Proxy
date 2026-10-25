package socks5

import (
	"net"
	"testing"
)

func TestReadRequestErrors(t *testing.T) {
	tests := []struct {
		name    string
		request []byte
	}{
		{
			name: "wrong version",
			request: []byte{
				0x04, // SOCKS4 instead of SOCKS5
				0x01,
				0x00,
				0x01,
				127, 0, 0, 1,
				0x01, 0xBB,
			},
		},
		{
			name: "zero-length domain",
			request: []byte{
				0x05, // SOCKS5
				0x01, // CONNECT
				0x00, // reserved
				0x03, // domain
				0x00, // invalid zero-length domain
			},
		},
		{
			name: "unsupported command",
			request: []byte{
				0x05,
				0x02, // BIND, not CONNECT
				0x00,
				0x01,
				127, 0, 0, 1,
				0x01, 0xBB,
			},
		},
		{
			name: "invalid reserved byte",
			request: []byte{
				0x05,
				0x01,
				0x01, // must be 0x00
				0x01,
				127, 0, 0, 1,
				0x01, 0xBB,
			},
		},
		{
			name: "unsupported address type",
			request: []byte{
				0x05,
				0x01,
				0x00,
				0x02, // unsupported ATYP
			},
		},
		{
			name: "truncated ipv4 request",
			request: []byte{
				0x05,
				0x01,
				0x00,
				0x01,
				127, 0, // only part of IPv4 address
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()

			done := make(chan error, 1)

			go func() {
				_, err := readRequest(serverConn)
				done <- err
			}()

			go func() {
				_, _ = clientConn.Write(tt.request)
				clientConn.Close()
			}()

			err := <-done

			if err == nil {
				t.Fatal("expected request parsing to fail, but it succeeded")
			}
		})
	}
}
