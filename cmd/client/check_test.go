package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/yedukrishna012/ghost-proxy/pkg/config"
)

func TestClientCheckHint(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "wrong PSK",
			err:  errors.New("authenticate: read authentication result: frame: read header: EOF"),
			want: "PSK does not match",
		},
		{
			name: "certificate",
			err:  errors.New("x509: certificate signed by unknown authority"),
			want: "certificate could not be verified",
		},
		{
			name: "unreachable",
			err:  errors.New("connect to Ghost server: dial tcp 203.0.113.10:443: connect: connection refused"),
			want: "gateway could not be reached",
		},
		{
			name: "timeout",
			err:  errors.New("dial tcp 203.0.113.10:443: i/o timeout"),
			want: "did not respond in time",
		},
		{
			name: "dns",
			err:  errors.New("dial tcp: lookup proxy.example.com: no such host"),
			want: "could not be resolved",
		},
		{
			name: "destination",
			err:  errors.New("destination host is not allowed"),
			want: "refused the test destination",
		},
		{
			name: "unknown",
			err:  errors.New("something unexpected"),
			want: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := clientCheckHint(test.err, "proxy.example.com:443")
			if !strings.Contains(got, test.want) {
				t.Fatalf("hint = %q, want it to contain %q", got, test.want)
			}
		})
	}
}

func TestClientCheckHintUsesConfiguredPort(t *testing.T) {
	hint := clientCheckHint(
		errors.New("connect to Ghost server: dial tcp 203.0.113.10:8443: connect: connection refused"),
		"203.0.113.10:8443",
	)
	if !strings.Contains(hint, "TCP 8443") {
		t.Fatalf("hint = %q, want it to mention TCP 8443", hint)
	}
}

func TestRunClientCheckRejectsInvalidTarget(t *testing.T) {
	err := runClientCheck(nil, config.Config{ServerAddress: "127.0.0.1:443"}, "not-a-host-port")
	if err == nil || !strings.Contains(err.Error(), "invalid --check-target") {
		t.Fatalf("expected target validation error, got %v", err)
	}
}
