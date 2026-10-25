package socks5

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type fuzzConn struct{ *bytes.Reader }

func (fuzzConn) Write(p []byte) (int, error)      { return len(p), nil }
func (fuzzConn) Close() error                     { return nil }
func (fuzzConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (fuzzConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (fuzzConn) SetDeadline(time.Time) error      { return nil }
func (fuzzConn) SetReadDeadline(time.Time) error  { return nil }
func (fuzzConn) SetWriteDeadline(time.Time) error { return nil }

func FuzzReadRequest(f *testing.F) {
	f.Add([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80})
	f.Add([]byte{5, 1, 0, 3, 1, 'x', 0, 80})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = readRequest(fuzzConn{bytes.NewReader(b)}) })
}
