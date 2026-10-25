package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/yedukrishna012/ghost-proxy/pkg/config"
)

const (
	defaultServerPort     = 443
	defaultFallbackAddr   = "127.0.0.1:8080"
	minServerPSKHexLength = 32
	releasePage           = "https://github.com/yedukrishna012/Ghost-Proxy/releases/latest"
)

type serverSetupUI struct {
	reader *bufio.Reader
	stdin  *os.File
	out    io.Writer
}

func newServerSetupUI(in io.Reader, out io.Writer) *serverSetupUI {
	ui := &serverSetupUI{reader: bufio.NewReader(in), out: out}
	if file, ok := in.(*os.File); ok {
		ui.stdin = file
	}
	return ui
}

func (u *serverSetupUI) interactive() bool {
	return u.stdin != nil && term.IsTerminal(int(u.stdin.Fd()))
}

func (u *serverSetupUI) ask(prompt, defaultValue string) (string, error) {
	if defaultValue != "" {
		fmt.Fprintf(u.out, "%s [%s]: ", prompt, defaultValue)
	} else {
		fmt.Fprintf(u.out, "%s: ", prompt)
	}

	line, err := u.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}

	value := strings.TrimSpace(line)
	if value == "" {
		return defaultValue, nil
	}
	return value, nil
}

func (u *serverSetupUI) askSecret(prompt string) (string, error) {
	fmt.Fprint(u.out, prompt)

	if u.stdin != nil && term.IsTerminal(int(u.stdin.Fd())) {
		value, err := term.ReadPassword(int(u.stdin.Fd()))
		fmt.Fprintln(u.out)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(value)), nil
	}

	line, err := u.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

type serverSetupOptions struct {
	ConfigPath     string
	EnvPath        string
	PublicHost     string
	Port           int
	CertFile       string
	KeyFile        string
	Fallback       string
	Allowed        string
	PSK            string
	ForcePSK       bool
	SelfSigned     bool
	Force          bool
	NonInteractive bool
	InviteFile     string
}

type serverSetupResult struct {
	Config     config.Config
	ConfigPath string
	EnvPath    string
	PSK        string
	CertFile   string
	KeyFile    string
	SelfSigned bool
}

type serverConfigFile struct {
	ListenAddress       string   `yaml:"listen_address"`
	PublicHost          string   `yaml:"public_host"`
	LogLevel            string   `yaml:"log_level"`
	CertFile            string   `yaml:"cert_file"`
	KeyFile             string   `yaml:"key_file"`
	FallbackAddress     string   `yaml:"fallback_address"`
	AllowedDestinations []string `yaml:"allowed_destinations"`
	PaddingEnabled      *bool    `yaml:"padding_enabled"`
	JitterMS            int      `yaml:"jitter_ms"`
	PprofAddress        string   `yaml:"pprof_address"`
}

// runServerSetup collects the minimum information needed to run a gateway and
// writes both the YAML config and the git-ignored environment file.
func runServerSetup(opts serverSetupOptions, ui *serverSetupUI) (serverSetupResult, error) {
	if opts.ConfigPath == "" || opts.EnvPath == "" {
		return serverSetupResult{}, errors.New("config and environment paths are required")
	}

	var existing config.Config
	loaded, err := config.Load(opts.ConfigPath)
	switch {
	case err == nil:
		existing = loaded
	case errors.Is(err, os.ErrNotExist):
		// First run.
	default:
		fmt.Fprintf(ui.out, "Could not read the existing configuration (%v). Starting fresh.\n\n", err)
	}

	if err := os.MkdirAll(filepath.Dir(opts.ConfigPath), 0o755); err != nil {
		return serverSetupResult{}, fmt.Errorf("create config directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(opts.EnvPath), 0o755); err != nil {
		return serverSetupResult{}, fmt.Errorf("create settings directory: %w", err)
	}

	fmt.Fprintln(ui.out)
	fmt.Fprintln(ui.out, "=== Ghost Proxy server setup ===")
	fmt.Fprintln(ui.out, "Press Enter to accept the value shown in [brackets].")
	fmt.Fprintln(ui.out)

	publicHost, err := resolvePublicHost(opts, existing, ui)
	if err != nil {
		return serverSetupResult{}, err
	}

	port, err := resolvePublicPort(opts, existing, ui)
	if err != nil {
		return serverSetupResult{}, err
	}

	certPath, keyPath, selfSigned, err := resolveServerCertificate(opts, existing, publicHost, ui)
	if err != nil {
		return serverSetupResult{}, err
	}

	psk, err := resolveServerPSK(opts, ui)
	if err != nil {
		return serverSetupResult{}, err
	}

	fallback, err := resolveFallback(opts, existing, ui)
	if err != nil {
		return serverSetupResult{}, err
	}

	allowed, err := resolveAllowedDestinations(opts, existing, ui)
	if err != nil {
		return serverSetupResult{}, err
	}

	listenHost := "0.0.0.0"
	if existing.ListenAddress != "" {
		if host, _, splitErr := net.SplitHostPort(existing.ListenAddress); splitErr == nil && host != "" {
			listenHost = host
		}
	}

	cfg := serverConfigFile{
		ListenAddress:       net.JoinHostPort(listenHost, strconv.Itoa(port)),
		PublicHost:          publicHost,
		LogLevel:            existing.LogLevel,
		CertFile:            configPathFor(certPath),
		KeyFile:             configPathFor(keyPath),
		FallbackAddress:     fallback,
		AllowedDestinations: allowed,
		PaddingEnabled:      existing.PaddingEnabled,
		JitterMS:            existing.JitterMS,
		PprofAddress:        existing.PprofAddress,
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.PaddingEnabled == nil {
		enabled := true
		cfg.PaddingEnabled = &enabled
	}

	configData, err := yaml.Marshal(cfg)
	if err != nil {
		return serverSetupResult{}, fmt.Errorf("encode configuration: %w", err)
	}
	if err := os.WriteFile(opts.ConfigPath, configData, 0o644); err != nil {
		return serverSetupResult{}, fmt.Errorf("save configuration: %w", err)
	}
	if err := writeServerEnvFile(opts.EnvPath, psk); err != nil {
		return serverSetupResult{}, err
	}
	if err := os.Setenv("GHOST_PSK", psk); err != nil {
		return serverSetupResult{}, fmt.Errorf("apply PSK: %w", err)
	}

	result := serverSetupResult{
		Config: config.Config{
			ListenAddress:       cfg.ListenAddress,
			PublicHost:          cfg.PublicHost,
			LogLevel:            cfg.LogLevel,
			CertFile:            cfg.CertFile,
			KeyFile:             cfg.KeyFile,
			FallbackAddress:     cfg.FallbackAddress,
			AllowedDestinations: cfg.AllowedDestinations,
			PaddingEnabled:      cfg.PaddingEnabled,
			JitterMS:            cfg.JitterMS,
			PprofAddress:        cfg.PprofAddress,
		},
		ConfigPath: opts.ConfigPath,
		EnvPath:    opts.EnvPath,
		PSK:        psk,
		CertFile:   certPath,
		KeyFile:    keyPath,
		SelfSigned: selfSigned,
	}

	invite := formatServerInvite(result)
	fmt.Fprintln(ui.out)
	fmt.Fprint(ui.out, invite)
	if opts.InviteFile != "" {
		if err := os.MkdirAll(filepath.Dir(opts.InviteFile), 0o700); err != nil {
			return serverSetupResult{}, fmt.Errorf("create invite directory: %w", err)
		}
		if err := os.WriteFile(opts.InviteFile, []byte(invite), 0o600); err != nil {
			return serverSetupResult{}, fmt.Errorf("write invite file: %w", err)
		}
		fmt.Fprintf(ui.out, "\nThe invite above is saved in %s (readable only by you).\n", opts.InviteFile)
	}

	return result, nil
}

func resolvePublicHost(opts serverSetupOptions, existing config.Config, ui *serverSetupUI) (string, error) {
	if opts.PublicHost != "" {
		return validatePublicHost(opts.PublicHost)
	}

	defaultHost := existing.PublicHost
	if defaultHost == "" && existing.CertFile != "" {
		if hosts, err := certificateHosts(existing.CertFile); err == nil && len(hosts) > 0 {
			defaultHost = hosts[0]
		}
	}
	if defaultHost == "" {
		defaultHost = "localhost"
	}

	if opts.NonInteractive || !ui.interactive() {
		return "", errors.New("--public-host is required when running without prompts")
	}

	for {
		value, err := ui.ask("Public host name or IP users will connect to", defaultHost)
		if err != nil {
			return "", err
		}
		host, err := validatePublicHost(value)
		if err != nil {
			fmt.Fprintf(ui.out, "  %v\n", err)
			continue
		}
		return host, nil
	}
}

func resolvePublicPort(opts serverSetupOptions, existing config.Config, ui *serverSetupUI) (int, error) {
	if opts.Port != 0 {
		if opts.Port < 1 || opts.Port > 65535 {
			return 0, errors.New("--public-port must be between 1 and 65535")
		}
		return opts.Port, nil
	}

	defaultPort := defaultServerPort
	if existing.ListenAddress != "" {
		if _, portText, err := net.SplitHostPort(existing.ListenAddress); err == nil {
			if parsed, err := strconv.Atoi(portText); err == nil && parsed > 0 {
				defaultPort = parsed
			}
		}
	}

	if opts.NonInteractive || !ui.interactive() {
		return defaultPort, nil
	}

	for {
		value, err := ui.ask("Public port", strconv.Itoa(defaultPort))
		if err != nil {
			return 0, err
		}
		port, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || port < 1 || port > 65535 {
			fmt.Fprintln(ui.out, "  Port must be between 1 and 65535.")
			continue
		}
		return port, nil
	}
}

func resolveServerCertificate(opts serverSetupOptions, existing config.Config, publicHost string, ui *serverSetupUI) (certPath, keyPath string, selfSigned bool, err error) {
	configDir := filepath.Dir(opts.ConfigPath)

	if opts.CertFile != "" || opts.KeyFile != "" {
		if opts.CertFile == "" || opts.KeyFile == "" {
			return "", "", false, errors.New("--cert-file and --key-file must be provided together")
		}
		certPath, keyPath, err = prepareCertificateFiles(opts.CertFile, opts.KeyFile, configDir, publicHost, opts.NonInteractive, opts.Force, ui)
		if err != nil {
			return "", "", false, err
		}
		return certPath, keyPath, isSelfSignedCertificate(certPath), nil
	}

	if opts.SelfSigned {
		certPath, keyPath, err = ensureSelfSignedCertificate(configDir, publicHost, opts.Force, opts.NonInteractive, ui)
		if err != nil {
			return "", "", false, err
		}
		return certPath, keyPath, true, nil
	}

	if opts.NonInteractive || !ui.interactive() {
		return "", "", false, errors.New("provide --cert-file and --key-file, or pass --self-signed")
	}

	leCert, leKey := letsEncryptPaths(publicHost)
	if filesExist(leCert, leKey) {
		certPath, keyPath, err = prepareCertificateFiles(leCert, leKey, configDir, publicHost, false, false, ui)
		if err != nil {
			return "", "", false, err
		}
		return certPath, keyPath, false, nil
	}

	for {
		fmt.Fprintln(ui.out)
		fmt.Fprintln(ui.out, "TLS certificate:")
		fmt.Fprintln(ui.out, "  1) Let's Encrypt certificate already on this machine")
		fmt.Fprintln(ui.out, "  2) Use existing certificate and key files")
		fmt.Fprintln(ui.out, "  3) Generate a self-signed certificate (testing only)")
		defaultChoice := "3"
		if existing.CertFile != "" && existing.KeyFile != "" && filesExist(existing.CertFile, existing.KeyFile) {
			defaultChoice = "2"
		}
		choice, err := ui.ask("Choose", defaultChoice)
		if err != nil {
			return "", "", false, err
		}

		switch strings.TrimSpace(choice) {
		case "1":
			if !filesExist(leCert, leKey) {
				fmt.Fprintf(ui.out, "  No certificate found at %s.\n", leCert)
				fmt.Fprintln(ui.out, "  On a Linux server, the included installer can obtain one automatically.")
				fmt.Fprintln(ui.out, "  Or run certbot first, then run this setup again.")
				continue
			}
			certPath, keyPath, err = prepareCertificateFiles(leCert, leKey, configDir, publicHost, false, false, ui)
			if err != nil {
				return "", "", false, err
			}
			return certPath, keyPath, false, nil
		case "2":
			certDefault := existing.CertFile
			keyDefault := existing.KeyFile
			certInput, err := ui.ask("Certificate chain path", certDefault)
			if err != nil {
				return "", "", false, err
			}
			keyInput, err := ui.ask("Private key path", keyDefault)
			if err != nil {
				return "", "", false, err
			}
			certPath, keyPath, err = prepareCertificateFiles(certInput, keyInput, configDir, publicHost, false, false, ui)
			if err != nil {
				fmt.Fprintf(ui.out, "  %v\n", err)
				continue
			}
			return certPath, keyPath, isSelfSignedCertificate(certPath), nil
		case "3":
			certPath, keyPath, err = ensureSelfSignedCertificate(configDir, publicHost, opts.Force, false, ui)
			if err != nil {
				return "", "", false, err
			}
			return certPath, keyPath, true, nil
		default:
			fmt.Fprintln(ui.out, "  Choose 1, 2, or 3.")
		}
	}
}

func prepareCertificateFiles(certSource, keySource, configDir, publicHost string, nonInteractive, force bool, ui *serverSetupUI) (string, string, error) {
	certSource = strings.TrimSpace(certSource)
	keySource = strings.TrimSpace(keySource)
	if certSource == "" || keySource == "" {
		return "", "", errors.New("certificate and key paths are required")
	}

	if _, err := validateCertificatePair(certSource, keySource, publicHost); err != nil {
		return "", "", err
	}

	certAbs, err := filepath.Abs(certSource)
	if err != nil {
		return "", "", fmt.Errorf("resolve certificate path: %w", err)
	}
	keyAbs, err := filepath.Abs(keySource)
	if err != nil {
		return "", "", fmt.Errorf("resolve key path: %w", err)
	}

	configAbs, err := filepath.Abs(configDir)
	if err != nil {
		return "", "", fmt.Errorf("resolve config directory: %w", err)
	}
	if filepath.Dir(certAbs) == configAbs && filepath.Dir(keyAbs) == configAbs {
		return certAbs, keyAbs, nil
	}

	certDest := filepath.Join(configAbs, "server.crt")
	keyDest := filepath.Join(configAbs, "server.key")
	if !force && (pathExists(certDest) || pathExists(keyDest)) {
		if nonInteractive || !ui.interactive() {
			return "", "", fmt.Errorf("certificate files already exist in %s; pass --force to replace them", configAbs)
		}
		answer, err := ui.ask("Certificate files already exist. Replace them?", "no")
		if err != nil {
			return "", "", err
		}
		if !isYes(answer) {
			return currentCertificatePair(configAbs, publicHost)
		}
	}

	certData, err := os.ReadFile(certAbs)
	if err != nil {
		return "", "", fmt.Errorf("read certificate: %w", err)
	}
	keyData, err := os.ReadFile(keyAbs)
	if err != nil {
		return "", "", fmt.Errorf("read private key: %w", err)
	}
	if err := os.WriteFile(certDest, certData, 0o644); err != nil {
		return "", "", fmt.Errorf("save certificate: %w", err)
	}
	if err := os.WriteFile(keyDest, keyData, 0o600); err != nil {
		return "", "", fmt.Errorf("save private key: %w", err)
	}
	if err := os.Chmod(keyDest, 0o600); err != nil {
		return "", "", fmt.Errorf("secure private key: %w", err)
	}
	if _, err := validateCertificatePair(certDest, keyDest, publicHost); err != nil {
		return "", "", err
	}
	return certDest, keyDest, nil
}

func currentCertificatePair(configDir, publicHost string) (string, string, error) {
	certPath := filepath.Join(configDir, "server.crt")
	keyPath := filepath.Join(configDir, "server.key")
	if !filesExist(certPath, keyPath) {
		return "", "", errors.New("existing certificate files were not found")
	}
	if _, err := validateCertificatePair(certPath, keyPath, publicHost); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func ensureSelfSignedCertificate(configDir, publicHost string, force, nonInteractive bool, ui *serverSetupUI) (string, string, error) {
	certPath := filepath.Join(configDir, "server.crt")
	keyPath := filepath.Join(configDir, "server.key")

	if filesExist(certPath, keyPath) && !force && isSelfSignedCertificate(certPath) {
		if _, err := validateCertificatePair(certPath, keyPath, publicHost); err == nil {
			if nonInteractive || !ui.interactive() {
				return certPath, keyPath, nil
			}
			answer, askErr := ui.ask("A self-signed certificate already exists. Generate a new one?", "no")
			if askErr != nil {
				return "", "", askErr
			}
			if !isYes(answer) {
				return certPath, keyPath, nil
			}
		}
	}

	if err := generateSelfSignedCertificate(publicHost, certPath, keyPath); err != nil {
		return "", "", err
	}
	fmt.Fprintf(ui.out, "Generated a self-signed certificate for %s.\n", publicHost)
	fmt.Fprintln(ui.out, "Users will need the server.crt file as their CA certificate.")
	return certPath, keyPath, nil
}

func generateSelfSignedCertificate(host, certPath, keyPath string) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"Ghost Proxy"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}
	if host == "localhost" {
		template.DNSNames = append(template.DNSNames, "localhost")
		template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return fmt.Errorf("create certificate directory: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("save certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("save private key: %w", err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return fmt.Errorf("secure private key: %w", err)
	}
	return nil
}

func resolveServerPSK(opts serverSetupOptions, ui *serverSetupUI) (string, error) {
	current := strings.TrimSpace(opts.PSK)
	if current == "" {
		current = strings.TrimSpace(os.Getenv("GHOST_PSK"))
	}
	if current != "" {
		if err := validateServerPSK(current); err != nil {
			return "", err
		}
	}

	if opts.ForcePSK && opts.PSK == "" {
		psk, err := generateServerPSK()
		if err != nil {
			return "", err
		}
		fmt.Fprintln(ui.out, "Generated a new PSK.")
		return psk, nil
	}

	if opts.PSK != "" {
		return current, nil
	}
	if opts.NonInteractive || !ui.interactive() {
		if current != "" {
			return current, nil
		}
		return generateServerPSK()
	}

	prompt := "PSK (press Enter to generate a secure key): "
	if current != "" {
		prompt = "PSK (press Enter to keep the current key, type 'generate' for a new one): "
	}

	for {
		value, err := ui.askSecret(prompt)
		if err != nil {
			return "", err
		}
		switch {
		case value == "" && current != "":
			return current, nil
		case value == "" || strings.EqualFold(value, "generate"):
			psk, err := generateServerPSK()
			if err != nil {
				return "", err
			}
			fmt.Fprintln(ui.out, "Generated a new PSK.")
			return psk, nil
		case validateServerPSK(value) != nil:
			fmt.Fprintf(ui.out, "  %v\n", validateServerPSK(value))
		default:
			return value, nil
		}
	}
}

func generateServerPSK() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generate PSK: %w", err)
	}
	return hex.EncodeToString(key), nil
}

func resolveFallback(opts serverSetupOptions, existing config.Config, ui *serverSetupUI) (string, error) {
	if opts.Fallback != "" {
		return normalizeFallback(opts.Fallback)
	}
	defaultValue := existing.FallbackAddress
	if defaultValue == "" {
		defaultValue = defaultFallbackAddr
	}
	if opts.NonInteractive || !ui.interactive() {
		return defaultValue, nil
	}
	for {
		value, err := ui.ask("Fallback HTTP decoy address (type none to disable)", defaultValue)
		if err != nil {
			return "", err
		}
		fallback, err := normalizeFallback(value)
		if err != nil {
			fmt.Fprintf(ui.out, "  %v\n", err)
			continue
		}
		return fallback, nil
	}
}

func resolveAllowedDestinations(opts serverSetupOptions, existing config.Config, ui *serverSetupUI) ([]string, error) {
	if opts.Allowed != "" {
		return parseAllowedDestinations(opts.Allowed)
	}
	if opts.NonInteractive || !ui.interactive() {
		return existing.AllowedDestinations, nil
	}
	defaultValue := strings.Join(existing.AllowedDestinations, ",")
	for {
		value, err := ui.ask("Allowed destinations (comma-separated hosts or CIDRs, blank = all)", defaultValue)
		if err != nil {
			return nil, err
		}
		allowed, err := parseAllowedDestinations(value)
		if err != nil {
			fmt.Fprintf(ui.out, "  %v\n", err)
			continue
		}
		return allowed, nil
	}
}

func parseAllowedDestinations(raw string) ([]string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || value == "*" || strings.EqualFold(value, "all") {
		return nil, nil
	}

	var rules []string
	for _, part := range strings.Split(value, ",") {
		rule := strings.TrimSpace(part)
		if rule == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(rule); err == nil {
			rules = append(rules, rule)
			continue
		}
		host, err := validatePublicHost(rule)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed destination %q: %w", rule, err)
		}
		rules = append(rules, host)
	}
	return rules, nil
}

func validatePublicHost(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")
	if value == "" {
		return "", errors.New("public host is required")
	}
	if strings.Contains(value, "://") {
		return "", errors.New("enter a host name or IP only, without http:// or https://")
	}
	if strings.ContainsAny(value, " \t\r\n/") {
		return "", errors.New("public host cannot contain spaces or slashes")
	}

	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), nil
	}
	if strings.Contains(value, ":") {
		return "", errors.New("do not include a port in the public host; use --public-port")
	}
	if len(value) > 253 {
		return "", errors.New("host name is too long")
	}
	if value != "localhost" {
		for _, label := range strings.Split(value, ".") {
			if len(label) == 0 || len(label) > 63 {
				return "", errors.New("host name contains an empty or too-long label")
			}
			if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return "", errors.New("host name labels cannot start or end with a hyphen")
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
					return "", errors.New("host name contains an invalid character")
				}
			}
		}
	}
	return value, nil
}

func normalizeFallback(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || value == "-" || strings.EqualFold(value, "none") {
		return "", nil
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", fmt.Errorf("fallback address must be host:port: %v", err)
	}
	if host == "" {
		return "", errors.New("fallback address must include a host")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("fallback port must be between 1 and 65535")
	}
	return net.JoinHostPort(host, portText), nil
}

func validateServerPSK(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("PSK is required")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return errors.New("PSK must be hexadecimal (0-9, a-f)")
	}
	if len(decoded)*2 < minServerPSKHexLength {
		return fmt.Errorf("PSK must be at least %d hexadecimal characters", minServerPSKHexLength)
	}
	return nil
}

func writeServerEnvFile(path, psk string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create settings directory: %w", err)
	}
	if err := os.WriteFile(path, []byte("GHOST_PSK="+psk+"\n"), 0o600); err != nil {
		return fmt.Errorf("save PSK: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure PSK file: %w", err)
	}
	return nil
}

func readPSKFromEnvFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(key) == "GHOST_PSK" {
			return strings.Trim(strings.TrimSpace(value), `"'`), nil
		}
	}
	return "", nil
}

func loadServerEnvFile(path string) error {
	if os.Getenv("GHOST_PSK") != "" {
		return nil
	}
	value, err := readPSKFromEnvFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if value != "" {
		return os.Setenv("GHOST_PSK", value)
	}
	return nil
}

func letsEncryptPaths(host string) (string, string) {
	base := filepath.Join("/etc/letsencrypt/live", host)
	return filepath.Join(base, "fullchain.pem"), filepath.Join(base, "privkey.pem")
}

func configPathFor(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	cwd, err := os.Getwd()
	if err == nil {
		if rel, err := filepath.Rel(cwd, absolute); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(absolute)
}

func filesExist(paths ...string) bool {
	for _, path := range paths {
		if path == "" || !pathExists(path) {
			return false
		}
	}
	return true
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isYes(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

func validateCertificatePair(certPath, keyPath, publicHost string) (*x509.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load certificate and key: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, errors.New("certificate file contains no certificates")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("certificate is not valid until %s", leaf.NotBefore.Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("certificate expired on %s", leaf.NotAfter.Format(time.RFC3339))
	}
	if publicHost != "" {
		if err := leaf.VerifyHostname(publicHost); err != nil {
			return nil, fmt.Errorf("certificate does not cover %q: %w", publicHost, err)
		}
	}
	return leaf, nil
}

func certificateHosts(certPath string) ([]string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("certificate file does not contain PEM data")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	var hosts []string
	hosts = append(hosts, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		hosts = append(hosts, ip.String())
	}
	if len(hosts) == 0 && leaf.Subject.CommonName != "" {
		hosts = append(hosts, leaf.Subject.CommonName)
	}
	return hosts, nil
}

func isSelfSignedCertificate(certPath string) bool {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return bytes.Equal(leaf.RawIssuer, leaf.RawSubject) &&
		leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
}

func formatServerInvite(result serverSetupResult) string {
	address := net.JoinHostPort(result.Config.PublicHost, portFromListen(result.Config.ListenAddress))
	var b strings.Builder
	fmt.Fprintln(&b, "=== Ghost Proxy access (keep this private) ===")
	fmt.Fprintf(&b, "Server address: %s\n", address)
	fmt.Fprintf(&b, "PSK:            %s\n", result.PSK)
	if result.SelfSigned {
		fmt.Fprintf(&b, "CA certificate: %s\n", result.CertFile)
		fmt.Fprintln(&b, "                Send this file to each user; they must enter its path in the client wizard.")
	} else {
		fmt.Fprintln(&b, "CA certificate: not needed (the gateway uses a trusted certificate)")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Send these details to each user privately.")
	fmt.Fprintf(&b, "Ghost Proxy client: %s\n", releasePage)
	fmt.Fprintln(&b, "Browser setting:    SOCKS5 127.0.0.1 port 1080")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Anyone with the PSK can use your gateway. Never post it publicly.")
	return b.String()
}

func portFromListen(listen string) string {
	_, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return strconv.Itoa(defaultServerPort)
	}
	return port
}

func checkServerConfiguration(cfg config.Config, configPath, envPath string, out io.Writer) error {
	if cfg.ListenAddress == "" {
		return errors.New("listen_address is required")
	}
	if _, _, err := net.SplitHostPort(cfg.ListenAddress); err != nil {
		return fmt.Errorf("listen_address is invalid: %w", err)
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return errors.New("cert_file and key_file are required")
	}

	leaf, err := validateCertificatePair(cfg.CertFile, cfg.KeyFile, cfg.PublicHost)
	if err != nil {
		return err
	}

	pskHex := strings.TrimSpace(os.Getenv("GHOST_PSK"))
	if pskHex == "" {
		return fmt.Errorf("GHOST_PSK is not set; add it to %s or the service environment", envPath)
	}
	psk, err := hex.DecodeString(pskHex)
	if err != nil {
		return fmt.Errorf("decode GHOST_PSK: %w", err)
	}
	if len(psk) < minPSKLen {
		return fmt.Errorf("GHOST_PSK must decode to at least %d bytes", minPSKLen)
	}

	if cfg.FallbackAddress != "" {
		if _, err := normalizeFallback(cfg.FallbackAddress); err != nil {
			return fmt.Errorf("fallback_address: %w", err)
		}
	}
	for _, rule := range cfg.AllowedDestinations {
		if _, err := parseAllowedDestinations(rule); err != nil {
			return fmt.Errorf("allowed_destinations: %w", err)
		}
	}

	publicAddress := cfg.ListenAddress
	if cfg.PublicHost != "" {
		publicAddress = net.JoinHostPort(cfg.PublicHost, portFromListen(cfg.ListenAddress))
	}

	fmt.Fprintln(out, "Configuration OK")
	fmt.Fprintf(out, "  Config:      %s\n", configPath)
	fmt.Fprintf(out, "  Listen:      %s\n", cfg.ListenAddress)
	fmt.Fprintf(out, "  Public:      %s\n", publicAddress)
	fmt.Fprintf(out, "  Certificate: %s (expires %s)\n", cfg.CertFile, leaf.NotAfter.Format("2006-01-02"))
	fmt.Fprintf(out, "  PSK:         set (%d hex characters)\n", len(pskHex))
	if cfg.FallbackAddress != "" {
		fmt.Fprintf(out, "  Fallback:    %s\n", cfg.FallbackAddress)
	} else {
		fmt.Fprintln(out, "  Fallback:    disabled")
	}

	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	remaining := time.Until(leaf.NotAfter)
	if lifetime > 0 && remaining < lifetime/5 {
		fmt.Fprintf(out, "  Warning:     certificate expires soon (%s remaining); check automatic renewal\n", remaining.Round(time.Hour))
	}

	if runtime.GOOS != "windows" {
		for _, check := range []struct {
			path string
			what string
		}{
			{cfg.KeyFile, "private key"},
			{envPath, "PSK file"},
		} {
			info, err := os.Stat(check.path)
			if err != nil {
				continue
			}
			if info.Mode().Perm()&0o007 != 0 {
				fmt.Fprintf(out, "  Warning:     %s %s is readable by other users; restrict it with chmod go-rwx\n", check.what, check.path)
			}
		}
	}

	return nil
}

func printServerInvite(cfg config.Config, out io.Writer) error {
	psk := strings.TrimSpace(os.Getenv("GHOST_PSK"))
	if psk == "" {
		return errors.New("GHOST_PSK is not set")
	}
	if err := validateServerPSK(psk); err != nil {
		return err
	}

	publicHost := cfg.PublicHost
	if publicHost == "" {
		hosts, err := certificateHosts(cfg.CertFile)
		if err != nil {
			return fmt.Errorf("read certificate: %w", err)
		}
		if len(hosts) > 0 {
			publicHost = hosts[0]
		}
	}
	if publicHost == "" {
		return errors.New("public_host is not configured; rerun setup or add public_host to the config")
	}

	result := serverSetupResult{
		Config:     cfg,
		PSK:        psk,
		CertFile:   cfg.CertFile,
		SelfSigned: isSelfSignedCertificate(cfg.CertFile),
	}
	result.Config.PublicHost = publicHost
	fmt.Fprint(out, formatServerInvite(result))
	return nil
}
