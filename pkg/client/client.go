package client

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/yedukrishna012/ghost-proxy/pkg/crypto"
	"github.com/yedukrishna012/ghost-proxy/pkg/frame"
	"github.com/yedukrishna012/ghost-proxy/pkg/transport"
)

type Client struct {
	ServerAddress  string
	ServerName     string
	CAFile         string
	PaddingEnabled *bool
	JitterMS       int
	tlsConfigOnce  sync.Once
	tlsConfig      *utls.Config
	tlsConfigErr   error
	PSK            []byte
}

func New(serverAddress, serverName string, psk []byte) *Client {
	return &Client{
		ServerAddress: serverAddress,
		ServerName:    serverName,
		PSK:           psk,
	}
}

func FromEnvironment(serverAddress, serverName string) (*Client, error) {
	value := os.Getenv("GHOST_PSK")
	if value == "" {
		return nil, fmt.Errorf("GHOST_PSK is not set")
	}

	psk, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode GHOST_PSK: %w", err)
	}

	if len(psk) < 16 {
		return nil, fmt.Errorf("GHOST_PSK must decode to at least 16 bytes")
	}

	return New(serverAddress, serverName, psk), nil
}

func (c *Client) Dial(address string) (net.Conn, error) {
	if c == nil {
		return nil, fmt.Errorf("client is nil")
	}

	if len(c.PSK) == 0 {
		return nil, fmt.Errorf("PSK is empty")
	}

	raw, err := net.DialTimeout("tcp", c.ServerAddress, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to Ghost server: %w", err)
	}

	c.tlsConfigOnce.Do(func() { c.tlsConfig, c.tlsConfigErr = transport.TLSConfigWithRootCA(c.ServerName, c.CAFile) })
	if c.tlsConfigErr != nil {
		raw.Close()
		return nil, c.tlsConfigErr
	}

	tlsConn, err := transport.DialUTLSWithConfig(raw, c.tlsConfig)
	if err != nil {
		return nil, err
	}

	exporter, err := transport.ExportKeyingMaterial(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	c2sKey, s2cKey, authKey, err := crypto.DeriveDirectionalKeys(c.PSK, exporter)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("derive session keys: %w", err)
	}

	if err := authenticate(tlsConn, authKey); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("authenticate: %w", err)
	}

	channel, err := transport.NewDirectionalDataChannel(c2sKey, s2cKey, 1, 2)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	paddingEnabled := true
	if c.PaddingEnabled != nil {
		paddingEnabled = *c.PaddingEnabled
	}
	channel.SetTrafficOptions(paddingEnabled, c.JitterMS)

	if err := channel.WriteConnectFrame(tlsConn, address); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("send target: %w", err)
	}

	return &DataConn{
		conn:    tlsConn,
		channel: channel,
		target:  address,
	}, nil
}

func authenticate(conn net.Conn, authKey []byte) error {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})
	proof, err := crypto.ClientProof(authKey)
	if err != nil {
		return err
	}
	if err := frame.WriteFrame(conn, &frame.Frame{Type: frame.TypeAuthResponse, Ciphertext: proof}); err != nil {
		return fmt.Errorf("write authentication response: %w", err)
	}
	ack, err := frame.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("read authentication result: %w", err)
	}
	if ack.Type != frame.TypeAuthSuccess {
		return fmt.Errorf("authentication rejected")
	}
	return nil
}

type DataConn struct {
	conn    net.Conn
	channel *transport.DataChannel
	target  string

	readMu  sync.Mutex
	writeMu sync.Mutex

	readBuffer []byte
}

func (c *DataConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.readBuffer) == 0 {
		payload, err := c.channel.ReadDataFrame(c.conn)
		if err != nil {
			return 0, err
		}

		c.readBuffer = payload
	}

	n := copy(p, c.readBuffer)
	c.readBuffer = c.readBuffer[n:]

	return n, nil
}

func (c *DataConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	const maxChunk = 1442

	total := 0

	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxChunk {
			chunk = p[:maxChunk]
		}

		if err := c.channel.WriteDataFrame(c.conn, chunk); err != nil {
			return total, err
		}

		total += len(chunk)
		p = p[len(chunk):]
	}

	return total, nil
}

func (c *DataConn) Close() error {
	return c.conn.Close()
}

func (c *DataConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *DataConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *DataConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *DataConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *DataConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
