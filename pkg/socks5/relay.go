package socks5

import (
	"io"
	"net"
)

func relay(clientConn, targetConn net.Conn) error {
	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(targetConn, clientConn)
		if c, ok := targetConn.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(clientConn, targetConn)
		if c, ok := clientConn.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
		errCh <- err
	}()

	first := <-errCh
	second := <-errCh
	if first != nil {
		return first
	}
	return second
}
