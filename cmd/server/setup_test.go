package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yedukrishna012/ghost-proxy/pkg/config"
)

func TestValidatePublicHost(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "IPv4", input: "203.0.113.10", want: "203.0.113.10"},
		{name: "IPv6 brackets", input: "[2001:db8::1]", want: "2001:db8::1"},
		{name: "domain", input: "proxy.example.com", want: "proxy.example.com"},
		{name: "localhost", input: "localhost", want: "localhost"},
		{name: "scheme", input: "https://proxy.example.com", wantErr: true},
		{name: "port", input: "proxy.example.com:443", wantErr: true},
		{name: "space", input: "proxy example.com", wantErr: true},
		{name: "empty", input: "", wantErr: true},
		{name: "bad label", input: "proxy..example.com", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := validatePublicHost(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestParseAllowedDestinations(t *testing.T) {
	tests := []struct {
		input   string
		want    []string
		wantErr bool
	}{
		{input: "", want: nil},
		{input: "all", want: nil},
		{input: "*", want: nil},
		{input: "example.com, 203.0.113.0/24, 198.51.100.7", want: []string{"example.com", "203.0.113.0/24", "198.51.100.7"}},
		{input: "https://example.com", wantErr: true},
		{input: "bad host", wantErr: true},
	}

	for _, test := range tests {
		got, err := parseAllowedDestinations(test.input)
		if test.wantErr {
			if err == nil {
				t.Fatalf("expected an error for %q, got %v", test.input, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", test.input, err)
		}
		if len(got) != len(test.want) {
			t.Fatalf("got %v, want %v", got, test.want)
		}
		for i := range got {
			if got[i] != test.want[i] {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		}
	}
}

func TestNormalizeFallback(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{input: "", want: ""},
		{input: "none", want: ""},
		{input: "-", want: ""},
		{input: "127.0.0.1:8080", want: "127.0.0.1:8080"},
		{input: "[::1]:8080", want: "[::1]:8080"},
		{input: "127.0.0.1", wantErr: true},
		{input: "127.0.0.1:0", wantErr: true},
	}

	for _, test := range tests {
		got, err := normalizeFallback(test.input)
		if test.wantErr {
			if err == nil {
				t.Fatalf("expected an error for %q, got %q", test.input, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", test.input, err)
		}
		if got != test.want {
			t.Fatalf("got %q, want %q", got, test.want)
		}
	}
}

func TestValidateServerPSK(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{input: strings.Repeat("ab", 32)},
		{input: "", wantErr: true},
		{input: "not-hex", wantErr: true},
		{input: "abcd", wantErr: true},
	}

	for _, test := range tests {
		err := validateServerPSK(test.input)
		if test.wantErr && err == nil {
			t.Fatalf("expected an error for %q", test.input)
		}
		if !test.wantErr && err != nil {
			t.Fatalf("unexpected error for %q: %v", test.input, err)
		}
	}
}

func TestRunServerSetupSelfSigned(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server.yaml")
	envPath := filepath.Join(dir, "environment")
	invitePath := filepath.Join(dir, "invite.txt")
	psk := strings.Repeat("cd", 32)

	t.Setenv("GHOST_PSK", "")
	var out bytes.Buffer
	result, err := runServerSetup(serverSetupOptions{
		ConfigPath:     configPath,
		EnvPath:        envPath,
		PublicHost:     "localhost",
		Port:           8443,
		Fallback:       "none",
		PSK:            psk,
		SelfSigned:     true,
		NonInteractive: true,
		InviteFile:     invitePath,
	}, newServerSetupUI(bytes.NewBuffer(nil), &out))
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	if result.PSK != psk {
		t.Fatalf("unexpected PSK: %s", result.PSK)
	}
	if result.Config.PublicHost != "localhost" {
		t.Fatalf("public host = %q", result.Config.PublicHost)
	}
	if result.Config.ListenAddress != "0.0.0.0:8443" {
		t.Fatalf("listen address = %q", result.Config.ListenAddress)
	}
	if result.Config.FallbackAddress != "" {
		t.Fatalf("fallback address = %q", result.Config.FallbackAddress)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.PublicHost != "localhost" || cfg.CertFile == "" || cfg.KeyFile == "" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	for _, path := range []string{cfg.CertFile, cfg.KeyFile, envPath, invitePath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
	}

	if runtime.GOOS != "windows" {
		if mode := fileMode(t, envPath); mode != 0o600 {
			t.Fatalf("environment mode = %o, want 600", mode)
		}
		if mode := fileMode(t, cfg.KeyFile); mode != 0o600 {
			t.Fatalf("private key mode = %o, want 600", mode)
		}
		if mode := fileMode(t, invitePath); mode != 0o600 {
			t.Fatalf("invite mode = %o, want 600", mode)
		}
		if mode := fileMode(t, cfg.CertFile); mode != 0o644 {
			t.Fatalf("certificate mode = %o, want 644", mode)
		}
	}

	invite, err := os.ReadFile(invitePath)
	if err != nil {
		t.Fatalf("read invite: %v", err)
	}
	if !strings.Contains(string(invite), "localhost:8443") || !strings.Contains(string(invite), psk) {
		t.Fatalf("invite is missing connection details:\n%s", invite)
	}
	if !strings.Contains(string(invite), "CA certificate") {
		t.Fatalf("self-signed invite is missing the CA certificate line:\n%s", invite)
	}

	var checkOut bytes.Buffer
	if err := checkServerConfiguration(cfg, configPath, envPath, &checkOut); err != nil {
		t.Fatalf("configuration check failed: %v", err)
	}
	if !strings.Contains(checkOut.String(), "Configuration OK") {
		t.Fatalf("unexpected check output:\n%s", checkOut.String())
	}
}

func TestRunServerSetupKeepsPSKAndRotatesOnRequest(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server.yaml")
	envPath := filepath.Join(dir, "environment")
	psk := strings.Repeat("ef", 32)

	t.Setenv("GHOST_PSK", "")
	opts := serverSetupOptions{
		ConfigPath:     configPath,
		EnvPath:        envPath,
		PublicHost:     "localhost",
		Port:           8443,
		Fallback:       "none",
		PSK:            psk,
		SelfSigned:     true,
		NonInteractive: true,
	}
	if _, err := runServerSetup(opts, newServerSetupUI(bytes.NewBuffer(nil), &bytes.Buffer{})); err != nil {
		t.Fatalf("first setup failed: %v", err)
	}

	// A second run without --force-psk keeps the existing key.
	opts.PSK = ""
	if _, err := runServerSetup(opts, newServerSetupUI(bytes.NewBuffer(nil), &bytes.Buffer{})); err != nil {
		t.Fatalf("second setup failed: %v", err)
	}
	kept, err := readPSKFromEnvFile(envPath)
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	if kept != psk {
		t.Fatalf("PSK changed unexpectedly: got %s, want %s", kept, psk)
	}

	// --force-psk generates a new key.
	opts.ForcePSK = true
	if _, err := runServerSetup(opts, newServerSetupUI(bytes.NewBuffer(nil), &bytes.Buffer{})); err != nil {
		t.Fatalf("rotation setup failed: %v", err)
	}
	rotated, err := readPSKFromEnvFile(envPath)
	if err != nil {
		t.Fatalf("read rotated env: %v", err)
	}
	if rotated == psk || len(rotated) != 64 {
		t.Fatalf("PSK was not rotated correctly: %q", rotated)
	}
}

func TestCheckServerConfigurationRejectsWrongHostAndPSK(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server.yaml")
	envPath := filepath.Join(dir, "environment")

	t.Setenv("GHOST_PSK", "")
	psk := strings.Repeat("12", 32)
	if _, err := runServerSetup(serverSetupOptions{
		ConfigPath:     configPath,
		EnvPath:        envPath,
		PublicHost:     "localhost",
		Port:           8443,
		Fallback:       "none",
		PSK:            psk,
		SelfSigned:     true,
		NonInteractive: true,
	}, newServerSetupUI(bytes.NewBuffer(nil), &bytes.Buffer{})); err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	wrongHost := cfg
	wrongHost.PublicHost = "example.com"
	if err := checkServerConfiguration(wrongHost, configPath, envPath, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("expected host coverage error, got %v", err)
	}

	t.Setenv("GHOST_PSK", "abcd")
	if err := checkServerConfiguration(cfg, configPath, envPath, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "at least") {
		t.Fatalf("expected PSK length error, got %v", err)
	}

	t.Setenv("GHOST_PSK", "")
	if err := checkServerConfiguration(cfg, configPath, envPath, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "GHOST_PSK is not set") {
		t.Fatalf("expected missing PSK error, got %v", err)
	}
}

func TestPrintServerInviteUsesCertificateHost(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server.yaml")
	envPath := filepath.Join(dir, "environment")

	t.Setenv("GHOST_PSK", "")
	psk := strings.Repeat("34", 32)
	result, err := runServerSetup(serverSetupOptions{
		ConfigPath:     configPath,
		EnvPath:        envPath,
		PublicHost:     "localhost",
		Port:           8443,
		Fallback:       "none",
		PSK:            psk,
		SelfSigned:     true,
		NonInteractive: true,
	}, newServerSetupUI(bytes.NewBuffer(nil), &bytes.Buffer{}))
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	cfg := result.Config
	cfg.PublicHost = ""
	var out bytes.Buffer
	if err := printServerInvite(cfg, &out); err != nil {
		t.Fatalf("print invite: %v", err)
	}
	if !strings.Contains(out.String(), "localhost:8443") || !strings.Contains(out.String(), psk) {
		t.Fatalf("unexpected invite:\n%s", out.String())
	}
}

func TestReadPSKFromEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "environment")
	if err := os.WriteFile(path, []byte("# comment\nexport GHOST_PSK=\"abc123\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := readPSKFromEnvFile(path)
	if err != nil {
		t.Fatalf("read PSK: %v", err)
	}
	if value != "abc123" {
		t.Fatalf("PSK = %q", value)
	}
	if !errors.Is(mustReadMissingPSK(t, filepath.Join(dir, "missing")), os.ErrNotExist) {
		t.Fatal("expected os.ErrNotExist")
	}
}

func mustReadMissingPSK(t *testing.T, path string) error {
	t.Helper()
	_, err := readPSKFromEnvFile(path)
	return err
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

func TestEnsureSelfSignedCertificateDoesNotKeepTrustedCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	issuer := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Certificate Authority"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if isSelfSignedCertificate(certPath) {
		t.Fatal("test certificate should not be self-signed")
	}

	ui := newServerSetupUI(bytes.NewBuffer(nil), &bytes.Buffer{})
	if _, _, err := ensureSelfSignedCertificate(dir, "localhost", false, true, ui); err != nil {
		t.Fatalf("ensure self-signed certificate: %v", err)
	}
	if !isSelfSignedCertificate(certPath) {
		t.Fatal("trusted certificate was kept instead of generating a self-signed certificate")
	}
	if _, err := validateCertificatePair(certPath, keyPath, "localhost"); err != nil {
		t.Fatalf("generated certificate is invalid: %v", err)
	}
}
