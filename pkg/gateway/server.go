package gateway

import (
	"bytes"
	"errors"
	"io"
	"net"
	"time"

	"github.com/yedukrishna012/ghost-proxy/pkg/logger"
)

// ExporterFunc returns the TLS exporter material for the established connection.
type ExporterFunc func(conn net.Conn) ([]byte, error)

// Server accepts connections and authenticates each one.
type Server struct {
	// PSK is the pre-shared key. Never logged.
	PSK []byte
	// Exporter supplies per-connection TLS exporter material.
	Exporter ExporterFunc
	// Prepare performs connection setup (including TLS handshake) per accepted peer.
	Prepare func(net.Conn) (net.Conn, error)
	// OnFallback receives consumed input for replay to the decoy.
	OnFallback func(net.Conn, io.Reader)
	// OnAuthenticated takes ownership of conn after a successful
	// handshake (tunnel handling will live here). If nil, conn is closed.
	OnAuthenticated func(conn net.Conn, s *AuthSession)
}

// Serve accepts connections on ln until ln is closed. Each connection
// is handled in its own goroutine.
func (srv *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			logger.Warn("accept failed", "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go srv.handle(conn)
	}
}

func (srv *Server) handle(conn net.Conn) {
	var consumed captureBuffer
	rawConn := &captureConn{Conn: conn, capture: &consumed}
	conn = rawConn
	if srv.Prepare != nil {
		prepared, err := srv.Prepare(conn)
		if err != nil {
			if srv.OnFallback != nil {
				srv.OnFallback(conn, io.MultiReader(bytes.NewReader(consumed.Bytes()), conn))
			} else {
				conn.Close()
			}
			return
		}
		rawConn.capture = io.Discard
		conn = prepared
	}
	remote := conn.RemoteAddr().String()

	exporter, err := srv.Exporter(conn)
	if err != nil {
		logger.Warn("exporter failed", "remote", remote, "err", err)
		conn.Close()
		return
	}

	session, err := NewAuthSession(srv.PSK, exporter)
	if err != nil {
		logger.Error("session setup failed", "remote", remote, "err", err)
		conn.Close()
		return
	}

	replay, authErr := session.AuthenticateReplay(conn)
	if authErr != nil {
		logger.Warn("authentication failed", "remote", remote, "err", authErr)
		if srv.OnFallback != nil {
			srv.OnFallback(conn, replay)
		} else {
			conn.Close()
		}
		return
	}

	logger.Info("client authenticated", "remote", remote)
	if srv.OnAuthenticated == nil {
		conn.Close()
		return
	}
	srv.OnAuthenticated(conn, session)
}

type captureBuffer struct{ b []byte }

func (c *captureBuffer) Write(p []byte) (int, error) { c.b = append(c.b, p...); return len(p), nil }
func (c *captureBuffer) Bytes() []byte               { return c.b }

type captureConn struct {
	net.Conn
	capture io.Writer
}

func (c *captureConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	if n > 0 {
		_, _ = c.capture.Write(p[:n])
	}
	return n, e
}
