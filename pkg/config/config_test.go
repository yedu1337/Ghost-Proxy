package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	cfg, err := Load("../../configs/client.yaml")
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.ListenAddress != "127.0.0.1:1080" {
		t.Errorf("unexpected listen address: %s", cfg.ListenAddress)
	}

	if cfg.ServerAddress != "127.0.0.1:443" {
		t.Errorf("unexpected server address: %s", cfg.ServerAddress)
	}

	if cfg.LogLevel != "info" {
		t.Errorf("unexpected log level: %s", cfg.LogLevel)
	}
}

func TestLoadValidatesPprofAddress(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{name: "disabled"},
		{name: "IPv4 loopback", address: "127.0.0.1:6060"},
		{name: "IPv6 loopback", address: "[::1]:6060"},
		{name: "all interfaces", address: "0.0.0.0:6060", wantErr: true},
		{name: "public address", address: "8.8.8.8:6060", wantErr: true},
		{name: "hostname", address: "localhost:6060", wantErr: true},
		{name: "invalid port", address: "127.0.0.1:70000", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "server.yaml")
			data := []byte("listen_address: '127.0.0.1:0'\npprof_address: '" + tt.address + "'\n")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Load() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
