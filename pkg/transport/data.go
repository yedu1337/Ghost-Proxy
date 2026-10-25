package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"time"

	"github.com/yedukrishna012/ghost-proxy/pkg/crypto"
	"github.com/yedukrishna012/ghost-proxy/pkg/frame"
	"github.com/yedukrishna012/ghost-proxy/pkg/padding"
)

// DataChannel provides the Ghost Proxy data-frame
// encode/pad/encrypt/decrypt/unpad/decode pipeline.
type DataChannel struct {
	AEAD                            *crypto.AEAD
	ReceiveAEAD                     *crypto.AEAD
	SendNonces                      *frame.NonceCounter
	sendDirection, receiveDirection byte
	receiveSequence                 uint64
	directional                     bool
	PaddingEnabled                  bool
	JitterMS                        int
}

// NewDataChannel creates a data channel from a session key.
func NewDataChannel(key []byte) (*DataChannel, error) {
	aead, err := crypto.NewAEAD(key)
	if err != nil {
		return nil, fmt.Errorf("transport: create data AEAD: %w", err)
	}

	nonces, err := frame.NewNonceCounter()
	if err != nil {
		return nil, fmt.Errorf("transport: create nonce counter: %w", err)
	}

	return &DataChannel{
		AEAD:           aead,
		ReceiveAEAD:    aead,
		SendNonces:     nonces,
		PaddingEnabled: true,
	}, nil
}

func (d *DataChannel) SetTrafficOptions(paddingEnabled bool, jitterMS int) {
	if d != nil {
		d.PaddingEnabled = paddingEnabled
		if jitterMS > 0 {
			d.JitterMS = jitterMS
		}
	}
}
func (d *DataChannel) delay() {
	if d.JitterMS > 0 {
		time.Sleep(time.Duration(rand.Intn(d.JitterMS+1)) * time.Millisecond)
	}
}

func NewDirectionalDataChannel(sendKey, receiveKey []byte, sendDirection, receiveDirection byte) (*DataChannel, error) {
	d, err := NewDataChannel(sendKey)
	if err != nil {
		return nil, err
	}
	r, err := crypto.NewAEAD(receiveKey)
	if err != nil {
		return nil, err
	}
	d.ReceiveAEAD = r
	d.sendDirection = sendDirection
	d.receiveDirection = receiveDirection
	d.directional = true
	return d, nil
}
func (d *DataChannel) aad(typ, direction byte, nonce [frame.NonceSize]byte) []byte {
	if !d.directional {
		return []byte{typ}
	}
	a := make([]byte, 10)
	a[0] = typ
	a[1] = direction
	copy(a[2:], nonce[4:])
	return a
}
func (d *DataChannel) checkSequence(nonce [frame.NonceSize]byte) error {
	if !d.directional {
		return nil
	}
	seq := binary.BigEndian.Uint64(nonce[4:])
	if seq != d.receiveSequence {
		return fmt.Errorf("transport: unexpected frame sequence %d, want %d", seq, d.receiveSequence)
	}
	d.receiveSequence++
	return nil
}

// WriteDataFrame performs:
//
//	EncodePayload -> Pad -> Seal -> WriteFrame
func (d *DataChannel) WriteDataFrame(w io.Writer, payload []byte) error {
	if d == nil || d.AEAD == nil || d.SendNonces == nil {
		return fmt.Errorf("transport: data channel is not initialized")
	}

	if w == nil {
		return fmt.Errorf("transport: writer is nil")
	}

	envelope, err := frame.EncodePayload(payload)
	if err != nil {
		return fmt.Errorf("transport: encode payload: %w", err)
	}

	padded := envelope
	if d.PaddingEnabled {
		padded, err = padding.Pad(envelope, d.AEAD.Overhead())
		if err != nil {
			return fmt.Errorf("transport: pad payload: %w", err)
		}
	}

	nonce := d.SendNonces.Next()

	ciphertext, err := d.AEAD.Seal(
		nonce[:],
		padded,
		d.aad(frame.TypeDataPayload, d.sendDirection, nonce),
	)
	if err != nil {
		return fmt.Errorf("transport: seal data frame: %w", err)
	}

	out := &frame.Frame{
		Type:       frame.TypeDataPayload,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	d.delay()

	if err := frame.WriteFrame(w, out); err != nil {
		return fmt.Errorf("transport: write data frame: %w", err)
	}

	return nil
}

// ReadDataFrame performs:
//
//	ReadFrame -> Open -> Unpad -> DecodePayload
func (d *DataChannel) ReadDataFrame(r io.Reader) ([]byte, error) {
	if d == nil || d.AEAD == nil {
		return nil, fmt.Errorf("transport: data channel is not initialized")
	}

	if r == nil {
		return nil, fmt.Errorf("transport: reader is nil")
	}

	in, err := frame.ReadFrame(r)
	if err != nil {
		return nil, fmt.Errorf("transport: read data frame: %w", err)
	}

	if in.Type != frame.TypeDataPayload {
		return nil, fmt.Errorf(
			"transport: unexpected frame type: 0x%02x",
			in.Type,
		)
	}
	if err := d.checkSequence(in.Nonce); err != nil {
		return nil, err
	}

	opened, err := d.ReceiveAEAD.Open(
		in.Nonce[:],
		in.Ciphertext,
		d.aad(in.Type, d.receiveDirection, in.Nonce),
	)
	if err != nil {
		return nil, fmt.Errorf("transport: open data frame: %w", err)
	}

	envelope, err := padding.Unpad(opened)
	if err != nil {
		return nil, fmt.Errorf("transport: unpad data frame: %w", err)
	}

	payload, err := frame.DecodePayload(envelope)
	if err != nil {
		return nil, fmt.Errorf("transport: decode payload: %w", err)
	}

	return payload, nil
}
