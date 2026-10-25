package transport

import (
	"bytes"
	"testing"

	"github.com/yedukrishna012/ghost-proxy/pkg/crypto"
)

func testDataKey() []byte {
	return bytes.Repeat([]byte{0x42}, crypto.KeySize)
}

func TestDataChannelRoundTrip(t *testing.T) {
	key := testDataKey()

	sender, err := NewDataChannel(key)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := NewDataChannel(key)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello ghost proxy")

	var buf bytes.Buffer

	if err := sender.WriteDataFrame(&buf, payload); err != nil {
		t.Fatal(err)
	}

	got, err := receiver.ReadDataFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", got, payload)
	}
}

func BenchmarkDataChannelRoundTrip(b *testing.B) {
	key := testDataKey()
	sender, err := NewDataChannel(key)
	if err != nil {
		b.Fatal(err)
	}
	receiver, err := NewDataChannel(key)
	if err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte("g"), 512)
	var wire bytes.Buffer
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wire.Reset()
		if err := sender.WriteDataFrame(&wire, payload); err != nil {
			b.Fatal(err)
		}
		if _, err := receiver.ReadDataFrame(&wire); err != nil {
			b.Fatal(err)
		}
	}
}

func TestDirectionalDataChannelSequenceAndAAD(t *testing.T) {
	c2s := bytes.Repeat([]byte{1}, 32)
	s2c := bytes.Repeat([]byte{2}, 32)
	client, err := NewDirectionalDataChannel(c2s, s2c, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewDirectionalDataChannel(s2c, c2s, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := client.WriteDataFrame(&wire, []byte("ordered")); err != nil {
		t.Fatal(err)
	}
	frameBytes := append([]byte(nil), wire.Bytes()...)
	got, err := server.ReadDataFrame(bytes.NewReader(frameBytes))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ordered" {
		t.Fatalf("got %q", got)
	}
	if _, err := server.ReadDataFrame(bytes.NewReader(frameBytes)); err == nil {
		t.Fatal("replayed frame was accepted")
	}
	wrongDirection, err := NewDirectionalDataChannel(s2c, c2s, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongDirection.ReadDataFrame(bytes.NewReader(frameBytes)); err == nil {
		t.Fatal("frame authenticated with wrong direction")
	}
}
