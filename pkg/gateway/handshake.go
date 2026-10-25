package gateway

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	ghostcrypto "github.com/yedukrishna012/ghost-proxy/pkg/crypto"
	"github.com/yedukrishna012/ghost-proxy/pkg/frame"
)

var ErrAuthFailed = errors.New("gateway: authentication failed")
var authTimeout = 5 * time.Second

// Authenticate runs the deprecated server-first handshake for compatibility.
//
// Deprecated: production handlers should use AuthenticateReplay.
func (s *AuthSession) Authenticate(conn net.Conn) error {
	// Deprecated legacy challenge exchange retained for protocol migration tests.
	if err := conn.SetDeadline(time.Now().Add(authTimeout)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})
	challenge, err := s.Challenge()
	if err != nil {
		return err
	}
	nc, err := frame.NewNonceCounter()
	if err != nil {
		return err
	}
	if err := frame.WriteFrame(conn, &frame.Frame{Type: frame.TypeAuthChallenge, Nonce: nc.Next(), Ciphertext: challenge}); err != nil {
		return err
	}
	f, err := frame.ReadFrame(conn)
	if err != nil || f.Type != frame.TypeAuthResponse {
		return ErrAuthFailed
	}
	aead, err := ghostcrypto.NewAEAD(s.DataKey())
	if err != nil {
		return err
	}
	response, err := aead.Open(f.Nonce[:], f.Ciphertext, []byte{f.Type})
	if err != nil {
		return ErrAuthFailed
	}
	ok, err := s.VerifyResponse(challenge, response)
	if err != nil || !ok {
		return ErrAuthFailed
	}
	return frame.WriteFrame(conn, &frame.Frame{Type: frame.TypeAuthSuccess})
}

// AuthenticateReplay reads the client's proof as the first TLS application
// frame. It returns a reader that replays every consumed byte on failure.
func (s *AuthSession) AuthenticateReplay(conn net.Conn) (io.Reader, error) {
	if err := conn.SetReadDeadline(time.Now().Add(authTimeout)); err != nil {
		return nil, err
	}
	defer conn.SetReadDeadline(time.Time{})
	br := bufio.NewReader(conn)
	var seen bytes.Buffer
	f, err := frame.ReadFrame(io.TeeReader(br, &seen))
	replay := io.MultiReader(bytes.NewReader(seen.Bytes()), br)
	if err != nil || f.Type != frame.TypeAuthResponse || !ghostcrypto.VerifyClientProof(s.authKey, f.Ciphertext) {
		return replay, ErrAuthFailed
	}
	if err := frame.WriteFrame(conn, &frame.Frame{Type: frame.TypeAuthSuccess}); err != nil {
		return replay, fmt.Errorf("gateway: send authentication success: %w", err)
	}
	return nil, nil
}
