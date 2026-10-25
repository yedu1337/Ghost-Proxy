package transport

import (
	"net"
	"testing"
	"time"
)

func TestConnectFrameRoundTrip(t *testing.T) {
	key := make([]byte, 32)

	clientChannel, err := NewDataChannel(key)
	if err != nil {
		t.Fatalf("client NewDataChannel: %v", err)
	}

	serverChannel, err := NewDataChannel(key)
	if err != nil {
		t.Fatalf("server NewDataChannel: %v", err)
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	target := "127.0.0.1:8080"

	writeErr := make(chan error, 1)

	go func() {
		writeErr <- clientChannel.WriteConnectFrame(
			client,
			target,
		)
	}()

	got, err := serverChannel.ReadConnectFrame(server)
	if err != nil {
		t.Fatalf("ReadConnectFrame: %v", err)
	}

	if got != target {
		t.Fatalf(
			"target mismatch: got %q want %q",
			got,
			target,
		)
	}

	select {
	case err := <-writeErr:
		if err != nil {
			t.Fatalf("WriteConnectFrame: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for WriteConnectFrame")
	}
}

func TestConnectFrameRejectsInvalidTarget(t *testing.T) {
	tests := []string{
		"",
		"127.0.0.1",
		"127.0.0.1:0",
		"127.0.0.1:65536",
		"example.com:notaport",
	}

	for _, target := range tests {
		if err := validateTarget(target); err == nil {
			t.Fatalf(
				"validateTarget(%q) unexpectedly succeeded",
				target,
			)
		}
	}
}
