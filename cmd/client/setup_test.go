package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yedukrishna012/ghost-proxy/pkg/config"
)

func TestNormalizeServerAddress(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantAddress string
		wantHost    string
		wantErr     bool
	}{
		{name: "host only", input: "proxy.example.com", wantAddress: "proxy.example.com:443", wantHost: "proxy.example.com"},
		{name: "host and port", input: "proxy.example.com:8443", wantAddress: "proxy.example.com:8443", wantHost: "proxy.example.com"},
		{name: "ipv4", input: "127.0.0.1:8443", wantAddress: "127.0.0.1:8443", wantHost: "127.0.0.1"},
		{name: "ipv6 without port", input: "::1", wantAddress: "[::1]:443", wantHost: "::1"},
		{name: "ipv6 with port", input: "[::1]:8443", wantAddress: "[::1]:8443", wantHost: "::1"},
		{name: "url rejected", input: "https://proxy.example.com", wantErr: true},
		{name: "spaces rejected", input: "proxy example.com", wantErr: true},
		{name: "empty rejected", input: "", wantErr: true},
		{name: "port out of range", input: "proxy.example.com:70000", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			address, host, err := normalizeServerAddress(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("normalizeServerAddress(%q) = %q, want error", test.input, address)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeServerAddress(%q): %v", test.input, err)
			}
			if address != test.wantAddress || host != test.wantHost {
				t.Fatalf("normalizeServerAddress(%q) = (%q, %q), want (%q, %q)", test.input, address, host, test.wantAddress, test.wantHost)
			}
		})
	}
}

func TestValidatePSK(t *testing.T) {
	valid := strings.Repeat("ab", 32)
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "valid 32 bytes", value: valid},
		{name: "valid 16 bytes", value: strings.Repeat("ab", 16)},
		{name: "too short", value: strings.Repeat("ab", 8), wantErr: true},
		{name: "not hex", value: strings.Repeat("zz", 32), wantErr: true},
		{name: "empty", value: "", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePSK(test.value)
			if test.wantErr && err == nil {
				t.Fatal("validatePSK returned nil, want error")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("validatePSK: %v", err)
			}
		})
	}
}

func TestLoadEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ghost.env")
	content := "# comment\nGHOST_PSK=0123456789abcdef0123456789abcdef\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GHOST_PSK", "")
	if err := loadEnvFile(path); err != nil {
		t.Fatalf("loadEnvFile: %v", err)
	}
	if got := os.Getenv("GHOST_PSK"); got != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("GHOST_PSK = %q", got)
	}
}

func TestLoadEnvFileDoesNotOverrideExistingValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ghost.env")
	if err := os.WriteFile(path, []byte("GHOST_PSK=fromfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GHOST_PSK", "fromenvironment")
	if err := loadEnvFile(path); err != nil {
		t.Fatalf("loadEnvFile: %v", err)
	}
	if got := os.Getenv("GHOST_PSK"); got != "fromenvironment" {
		t.Fatalf("GHOST_PSK = %q, want environment value", got)
	}
}

func TestRunSetupWritesConfigAndEnv(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "configs", "client.yaml")
	envPath := filepath.Join(dir, "ghost.env")
	psk := strings.Repeat("ab", 32)

	t.Setenv("GHOST_PSK", "")
	input := "proxy.example.com:8443\n\n\n" + psk + "\n"
	var out bytes.Buffer
	if err := runSetup(cfgPath, envPath, newSetupUI(strings.NewReader(input), &out)); err != nil {
		t.Fatalf("runSetup: %v", err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.ServerAddress != "proxy.example.com:8443" {
		t.Fatalf("server address = %q", cfg.ServerAddress)
	}
	if cfg.ServerName != "proxy.example.com" {
		t.Fatalf("server name = %q", cfg.ServerName)
	}
	if cfg.CAFile != "" {
		t.Fatalf("ca file = %q, want empty", cfg.CAFile)
	}
	if cfg.ListenAddress != defaultListenAddress {
		t.Fatalf("listen address = %q", cfg.ListenAddress)
	}
	if cfg.PaddingEnabled == nil || !*cfg.PaddingEnabled {
		t.Fatal("padding should be enabled")
	}

	envData, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	if string(envData) != "GHOST_PSK="+psk+"\n" {
		t.Fatalf("env data = %q", string(envData))
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(envPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("env mode = %o, want 600", info.Mode().Perm())
		}
	}
}

func TestRunSetupCopiesCACertificate(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "configs", "client.yaml")
	envPath := filepath.Join(dir, "ghost.env")
	caSource := filepath.Join(dir, "provided-ca.pem")
	writeTestCertificate(t, caSource)
	psk := strings.Repeat("cd", 32)

	t.Setenv("GHOST_PSK", "")
	input := "proxy.example.com\n\n" + caSource + "\n" + psk + "\n"
	var out bytes.Buffer
	if err := runSetup(cfgPath, envPath, newSetupUI(strings.NewReader(input), &out)); err != nil {
		t.Fatalf("runSetup: %v", err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.CAFile != "server.crt" {
		t.Fatalf("ca file = %q, want server.crt", cfg.CAFile)
	}
	copied, err := os.ReadFile(filepath.Join(filepath.Dir(cfgPath), "server.crt"))
	if err != nil {
		t.Fatalf("read copied CA: %v", err)
	}
	original, err := os.ReadFile(caSource)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copied, original) {
		t.Fatal("copied CA does not match the source certificate")
	}
}

func TestRunSetupRejectsInvalidPSKThenAccepts(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "configs", "client.yaml")
	envPath := filepath.Join(dir, "ghost.env")
	psk := strings.Repeat("ef", 32)

	t.Setenv("GHOST_PSK", "")
	input := "proxy.example.com\n\n\nnot-hex\n" + psk + "\n"
	var out bytes.Buffer
	if err := runSetup(cfgPath, envPath, newSetupUI(strings.NewReader(input), &out)); err != nil {
		t.Fatalf("runSetup: %v", err)
	}
	if !strings.Contains(out.String(), "PSK must be hexadecimal") {
		t.Fatalf("expected invalid PSK warning, got:\n%s", out.String())
	}
}

func writeTestCertificate(t *testing.T, path string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
