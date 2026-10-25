package transport

import (
	"bytes"
	"testing"

	"github.com/yedukrishna012/ghost-proxy/pkg/crypto"
	"github.com/yedukrishna012/ghost-proxy/pkg/frame"
)

func TestDataChannelRoundTripEdgePayloads(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, crypto.KeySize)

	// The payload limits below correspond to the padding block boundaries:
	// 512 - 16 byte AEAD overhead - 2 byte envelope prefix = 494
	// 1024 - 16 byte AEAD overhead - 2 byte envelope prefix = 1006
	// 1460 - 16 byte AEAD overhead - 2 byte envelope prefix = 1442.
	payloads := []struct {
		name string
		size int
	}{
		{name: "empty", size: 0},
		{name: "one_byte", size: 1},
		{name: "just_below_512", size: 493},
		{name: "exact_512_boundary", size: 494},
		{name: "just_above_512", size: 495},
		{name: "just_below_1024", size: 1005},
		{name: "exact_1024_boundary", size: 1006},
		{name: "just_above_1024", size: 1007},
		{name: "just_below_1460", size: 1441},
		{name: "exact_1460_boundary", size: 1442},
	}

	for _, tc := range payloads {
		t.Run(tc.name, func(t *testing.T) {
			sender, err := NewDataChannel(key)
			if err != nil {
				t.Fatal(err)
			}

			receiver, err := NewDataChannel(key)
			if err != nil {
				t.Fatal(err)
			}

			payload := bytes.Repeat([]byte{0xAB}, tc.size)

			var buf bytes.Buffer

			if err := sender.WriteDataFrame(&buf, payload); err != nil {
				t.Fatalf("WriteDataFrame(payload=%d) failed: %v", tc.size, err)
			}

			got, err := receiver.ReadDataFrame(&buf)
			if err != nil {
				t.Fatalf("ReadDataFrame(payload=%d) failed: %v", tc.size, err)
			}

			if !bytes.Equal(got, payload) {
				t.Fatalf(
					"payload mismatch: got %d bytes, want %d bytes",
					len(got),
					len(payload),
				)
			}
		})
	}
}

func TestDataChannelRoundTripMultipleEdgeFrames(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, crypto.KeySize)

	sender, err := NewDataChannel(key)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := NewDataChannel(key)
	if err != nil {
		t.Fatal(err)
	}

	payloads := [][]byte{
		{},
		bytes.Repeat([]byte{0x11}, 494),
		bytes.Repeat([]byte{0x22}, 1006),
		bytes.Repeat([]byte{0x33}, 1442),
		[]byte("final frame"),
	}

	var buf bytes.Buffer

	for i, payload := range payloads {
		if err := sender.WriteDataFrame(&buf, payload); err != nil {
			t.Fatalf("WriteDataFrame frame %d failed: %v", i, err)
		}
	}

	for i, want := range payloads {
		got, err := receiver.ReadDataFrame(&buf)
		if err != nil {
			t.Fatalf("ReadDataFrame frame %d failed: %v", i, err)
		}

		if !bytes.Equal(got, want) {
			t.Fatalf(
				"frame %d payload mismatch: got %d bytes, want %d bytes",
				i,
				len(got),
				len(want),
			)
		}
	}
}

func TestDataChannelRejectsOversizedPayload(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, crypto.KeySize)

	sender, err := NewDataChannel(key)
	if err != nil {
		t.Fatal(err)
	}

	// 1443 bytes produces a 1445-byte envelope, which exceeds the
	// largest usable padding target: 1460 - 16 = 1444.
	payload := bytes.Repeat([]byte{0xCD}, 1443)

	var buf bytes.Buffer

	if err := sender.WriteDataFrame(&buf, payload); err == nil {
		t.Fatal("expected oversized payload to be rejected")
	}
}

func TestDataChannelRejectsWrongFrameType(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, crypto.KeySize)

	sender, err := NewDataChannel(key)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := NewDataChannel(key)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer

	payload := []byte("wrong frame type")

	// Create a valid encrypted data payload first.
	envelope, err := frame.EncodePayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	nonce := sender.SendNonces.Next()

	ciphertext, err := sender.AEAD.Seal(
		nonce[:],
		envelope,
		[]byte{frame.TypeAuthResponse},
	)
	if err != nil {
		t.Fatal(err)
	}

	testFrame := &frame.Frame{
		Type:       frame.TypeAuthResponse,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}

	if err := frame.WriteFrame(&buf, testFrame); err != nil {
		t.Fatal(err)
	}

	if _, err := receiver.ReadDataFrame(&buf); err == nil {
		t.Fatal("expected wrong frame type to be rejected")
	}
}
