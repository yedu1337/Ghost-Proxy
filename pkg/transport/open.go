package transport

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/yedukrishna012/ghost-proxy/pkg/frame"
	"github.com/yedukrishna012/ghost-proxy/pkg/padding"
)

const MaxTargetAddressLen = 1024

// WriteConnectFrame sends the destination address using:
//
//	EncodePayload -> Pad -> Seal -> WriteFrame
func (d *DataChannel) WriteConnectFrame(w io.Writer, target string) error {
	if d == nil || d.AEAD == nil || d.SendNonces == nil {
		return fmt.Errorf("transport: data channel is not initialized")
	}

	if w == nil {
		return fmt.Errorf("transport: writer is nil")
	}

	if err := validateTarget(target); err != nil {
		return err
	}

	envelope, err := frame.EncodePayload([]byte(target))
	if err != nil {
		return fmt.Errorf("transport: encode target: %w", err)
	}

	padded := envelope
	if d.PaddingEnabled {
		padded, err = padding.Pad(envelope, d.AEAD.Overhead())
		if err != nil {
			return fmt.Errorf("transport: pad target: %w", err)
		}
	}

	nonce := d.SendNonces.Next()

	ciphertext, err := d.AEAD.Seal(
		nonce[:],
		padded,
		d.aad(frame.TypeConnOpen, d.sendDirection, nonce),
	)
	if err != nil {
		return fmt.Errorf("transport: seal target: %w", err)
	}

	out := &frame.Frame{
		Type:       frame.TypeConnOpen,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	d.delay()

	if err := frame.WriteFrame(w, out); err != nil {
		return fmt.Errorf("transport: write connect frame: %w", err)
	}

	return nil
}

// ReadConnectFrame receives and validates the encrypted destination address.
func (d *DataChannel) ReadConnectFrame(r io.Reader) (string, error) {
	if d == nil || d.AEAD == nil {
		return "", fmt.Errorf("transport: data channel is not initialized")
	}

	if r == nil {
		return "", fmt.Errorf("transport: reader is nil")
	}

	in, err := frame.ReadFrame(r)
	if err != nil {
		return "", fmt.Errorf("transport: read connect frame: %w", err)
	}

	if in.Type != frame.TypeConnOpen {
		return "", fmt.Errorf(
			"transport: unexpected frame type: 0x%02x",
			in.Type,
		)
	}
	if err := d.checkSequence(in.Nonce); err != nil {
		return "", err
	}

	opened, err := d.ReceiveAEAD.Open(
		in.Nonce[:],
		in.Ciphertext,
		d.aad(in.Type, d.receiveDirection, in.Nonce),
	)
	if err != nil {
		return "", fmt.Errorf(
			"transport: open connect frame: %w",
			err,
		)
	}

	envelope, err := padding.Unpad(opened)
	if err != nil {
		return "", fmt.Errorf(
			"transport: unpad target: %w",
			err,
		)
	}

	payload, err := frame.DecodePayload(envelope)
	if err != nil {
		return "", fmt.Errorf(
			"transport: decode target: %w",
			err,
		)
	}

	target := string(payload)

	if err := validateTarget(target); err != nil {
		return "", err
	}

	return target, nil
}

func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("transport: target address is empty")
	}

	if len(target) > MaxTargetAddressLen {
		return fmt.Errorf(
			"transport: target address exceeds %d bytes",
			MaxTargetAddressLen,
		)
	}

	host, portString, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf(
			"transport: invalid target address %q: %w",
			target,
			err,
		)
	}

	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("transport: target host is empty")
	}

	port, err := strconv.Atoi(portString)
	if err != nil {
		return fmt.Errorf(
			"transport: invalid target port %q",
			portString,
		)
	}

	if port < 1 || port > 65535 {
		return fmt.Errorf(
			"transport: target port out of range: %d",
			port,
		)
	}

	return nil
}
