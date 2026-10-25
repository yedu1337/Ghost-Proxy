package gateway

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	ghostcrypto "github.com/yedukrishna012/ghost-proxy/pkg/crypto"
	"github.com/yedukrishna012/ghost-proxy/pkg/frame"
	"github.com/yedukrishna012/ghost-proxy/pkg/padding"
)

const DestinationDialTimeout = 10 * time.Second
const maxTargetAddressLen = 1024

type TunnelOptions struct {
	AllowedDestinations []string
	PaddingEnabled      *bool
	JitterMS            int
}

func ServeTunnel(conn net.Conn, session *AuthSession) error {
	return ServeTunnelWithPolicy(conn, session, nil)
}

// ServeTunnelWithPolicy rejects private destinations and optionally restricts
// destinations to exact hosts/IPs or configured CIDRs.
func ServeTunnelWithPolicy(conn net.Conn, session *AuthSession, allow []string) error {
	return serveTunnel(conn, session, func(target string) (net.Conn, error) { return dialPublicDestination(target, allow) })
}
func ServeTunnelWithOptions(conn net.Conn, session *AuthSession, options TunnelOptions) error {
	return serveTunnelOptions(conn, session, options, func(target string) (net.Conn, error) {
		return dialPublicDestination(target, options.AllowedDestinations)
	})
}
func serveTunnel(conn net.Conn, session *AuthSession, dial func(string) (net.Conn, error)) error {
	return serveTunnelOptions(conn, session, TunnelOptions{}, dial)
}
func serveTunnelOptions(conn net.Conn, session *AuthSession, options TunnelOptions, dial func(string) (net.Conn, error)) error {
	if conn == nil {
		return fmt.Errorf("gateway: connection is nil")
	}
	if session == nil {
		return fmt.Errorf("gateway: auth session is nil")
	}
	channel, err := newTunnelChannel(session, options)
	if err != nil {
		return err
	}
	target, err := channel.readConnect(conn)
	if err != nil {
		return fmt.Errorf("gateway: read connect frame: %w", err)
	}
	destination, err := dial(target)
	if err != nil {
		return fmt.Errorf("gateway: connect to %q: %w", target, err)
	}
	defer destination.Close()
	errs := make(chan error, 2)
	go func() { errs <- forwardTunnelToDestination(conn, destination, channel) }()
	go func() { errs <- forwardDestinationToTunnel(destination, conn, channel) }()
	return <-errs
}

func dialPublicDestination(target string, allow []string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", host)
	if err != nil {
		return nil, err
	}
	if len(allow) > 0 {
		permitted := false
		for _, rule := range allow {
			if strings.EqualFold(rule, host) {
				permitted = true
				break
			}
			if _, network, e := net.ParseCIDR(rule); e == nil {
				for _, ip := range ips {
					if network.Contains(ip) {
						permitted = true
					}
				}
			}
		}
		if !permitted {
			return nil, fmt.Errorf("destination host is not allowed")
		}
	}
	for _, ip := range ips {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, fmt.Errorf("destination resolves to a prohibited address")
		}
	}
	var last error
	for _, ip := range ips {
		c, e := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), DestinationDialTimeout)
		if e == nil {
			return c, nil
		}
		last = e
	}
	if last == nil {
		last = fmt.Errorf("destination has no addresses")
	}
	return nil, last
}

func validateTunnelTarget(target string) error {
	if target == "" {
		return fmt.Errorf("gateway: target address is empty")
	}
	if len(target) > maxTargetAddressLen {
		return fmt.Errorf("gateway: target address exceeds %d bytes", maxTargetAddressLen)
	}
	host, p, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("gateway: invalid target address %q: %w", target, err)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("gateway: target host is empty")
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("gateway: target port out of range")
	}
	return nil
}

type tunnelChannel struct {
	send, receive  *ghostcrypto.AEAD
	nonces         *frame.NonceCounter
	received       uint64
	paddingEnabled bool
	jitterMS       int
}

func newTunnelChannel(s *AuthSession, options TunnelOptions) (*tunnelChannel, error) {
	send, e := ghostcrypto.NewAEAD(s.ServerToClientKey())
	if e != nil {
		return nil, e
	}
	recv, e := ghostcrypto.NewAEAD(s.ClientToServerKey())
	if e != nil {
		return nil, e
	}
	n, e := frame.NewNonceCounter()
	if e != nil {
		return nil, e
	}
	paddingEnabled := true
	if options.PaddingEnabled != nil {
		paddingEnabled = *options.PaddingEnabled
	}
	return &tunnelChannel{send: send, receive: recv, nonces: n, paddingEnabled: paddingEnabled, jitterMS: options.JitterMS}, nil
}
func aad(typ, dir byte, seq uint64) []byte {
	b := make([]byte, 10)
	b[0] = typ
	b[1] = dir
	binary.BigEndian.PutUint64(b[2:], seq)
	return b
}
func (c *tunnelChannel) read(r io.Reader, typ byte) ([]byte, error) {
	f, e := frame.ReadFrame(r)
	if e != nil {
		return nil, e
	}
	if f.Type != typ {
		return nil, fmt.Errorf("gateway: unexpected frame type 0x%02x", f.Type)
	}
	seq := binary.BigEndian.Uint64(f.Nonce[4:])
	if seq != c.received {
		return nil, fmt.Errorf("gateway: frame sequence %d, expected %d", seq, c.received)
	}
	plain, e := c.receive.Open(f.Nonce[:], f.Ciphertext, aad(typ, 1, seq))
	if e != nil {
		return nil, e
	}
	c.received++
	envelope, e := padding.Unpad(plain)
	if e != nil {
		return nil, e
	}
	return frame.DecodePayload(envelope)
}
func (c *tunnelChannel) write(w io.Writer, typ byte, payload []byte) error {
	env, e := frame.EncodePayload(payload)
	if e != nil {
		return e
	}
	p := env
	if c.paddingEnabled {
		p, e = padding.Pad(env, c.send.Overhead())
		if e != nil {
			return e
		}
	}
	nonce := c.nonces.Next()
	seq := binary.BigEndian.Uint64(nonce[4:])
	ct, e := c.send.Seal(nonce[:], p, aad(typ, 2, seq))
	if e != nil {
		return e
	}
	if c.jitterMS > 0 {
		time.Sleep(time.Duration(rand.Intn(c.jitterMS+1)) * time.Millisecond)
	}
	return frame.WriteFrame(w, &frame.Frame{Type: typ, Nonce: nonce, Ciphertext: ct})
}
func (c *tunnelChannel) readConnect(r io.Reader) (string, error) {
	payload, e := c.read(r, frame.TypeConnOpen)
	if e != nil {
		return "", e
	}
	target := string(payload)
	return target, validateTunnelTarget(target)
}

func forwardTunnelToDestination(tunnel, destination net.Conn, channel *tunnelChannel) error {
	for {
		payload, err := channel.read(tunnel, frame.TypeDataPayload)
		if err != nil {
			return err
		}
		if err := writeAll(destination, payload); err != nil {
			return err
		}
	}
}
func forwardDestinationToTunnel(destination, tunnel net.Conn, channel *tunnelChannel) error {
	buffer := make([]byte, 32*1024)
	max := padding.BlockSizes[len(padding.BlockSizes)-1] - channel.send.Overhead() - 2
	for {
		n, err := destination.Read(buffer)
		if n > 0 {
			for data := buffer[:n]; len(data) > 0; {
				size := len(data)
				if size > max {
					size = max
				}
				if e := channel.write(tunnel, frame.TypeDataPayload, data[:size]); e != nil {
					return e
				}
				data = data[size:]
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[n:]
	}
	return nil
}
