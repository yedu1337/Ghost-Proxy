package main

import (
	"bufio"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/yedukrishna012/ghost-proxy/pkg/config"
)

const (
	defaultListenAddress = "127.0.0.1:1080"
	defaultServerPort    = "443"
	minPSKHexLength      = 32
)

type clientConfigFile struct {
	ListenAddress  string `yaml:"listen_address"`
	ServerAddress  string `yaml:"server_address"`
	ServerName     string `yaml:"server_name"`
	CAFile         string `yaml:"ca_file"`
	LogLevel       string `yaml:"log_level"`
	PaddingEnabled *bool  `yaml:"padding_enabled"`
	JitterMS       int    `yaml:"jitter_ms"`
}

type setupUI struct {
	reader *bufio.Reader
	stdin  *os.File
	out    io.Writer
}

func newSetupUI(in io.Reader, out io.Writer) *setupUI {
	ui := &setupUI{reader: bufio.NewReader(in), out: out}
	if file, ok := in.(*os.File); ok {
		ui.stdin = file
	}
	return ui
}

func (u *setupUI) ask(prompt, defaultValue string) (string, error) {
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

func (u *setupUI) askSecret(prompt string) (string, error) {
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

// runSetup collects the minimum information needed to run the client and
// writes both the YAML config and the git-ignored ghost.env file.
func runSetup(cfgPath, envPath string, ui *setupUI) error {
	var existing config.Config
	loaded, err := config.Load(cfgPath)
	switch {
	case err == nil:
		existing = loaded
	case errors.Is(err, os.ErrNotExist):
		// First run.
	default:
		fmt.Fprintf(ui.out, "Could not read the existing configuration (%v). Starting fresh.\n\n", err)
	}

	currentPSK := strings.TrimSpace(os.Getenv("GHOST_PSK"))

	fmt.Fprintln(ui.out)
	fmt.Fprintln(ui.out, "=== Ghost Proxy setup ===")
	fmt.Fprintln(ui.out, "Press Enter to accept the value shown in [brackets].")
	fmt.Fprintln(ui.out)

	var serverAddress, serverHost string
	for {
		raw, err := ui.ask("Server address (host:port from your provider)", existing.ServerAddress)
		if err != nil {
			return err
		}

		address, host, err := normalizeServerAddress(raw)
		if err != nil {
			fmt.Fprintf(ui.out, "  %v\n", err)
			continue
		}
		serverAddress, serverHost = address, host
		break
	}

	defaultName := existing.ServerName
	if defaultName == "" {
		defaultName = serverHost
	}
	serverName, err := ui.ask("TLS server name (usually the same host)", defaultName)
	if err != nil {
		return err
	}
	if strings.TrimSpace(serverName) == "" {
		serverName = defaultName
	}

	defaultCA := existingCAPath(cfgPath, existing.CAFile)
	caRelative := ""
	for {
		caInput, err := ui.ask("CA certificate path (blank = system trust, type none to clear)", defaultCA)
		if err != nil {
			return err
		}
		caPath := strings.TrimSpace(caInput)
		if caPath == "" || caPath == "-" || strings.EqualFold(caPath, "none") {
			break
		}

		source, err := expandPath(caPath)
		if err != nil {
			fmt.Fprintf(ui.out, "  %v\n", err)
			continue
		}
		certPEM, err := os.ReadFile(source)
		if err != nil {
			fmt.Fprintf(ui.out, "  Could not read the CA certificate: %v\n", err)
			continue
		}
		if err := validateCertificatePEM(certPEM); err != nil {
			fmt.Fprintf(ui.out, "  %v\n", err)
			continue
		}

		destination := filepath.Join(filepath.Dir(cfgPath), "server.crt")
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return fmt.Errorf("create config directory: %w (move Ghost Proxy to a folder you can write to, such as Desktop or Documents)", err)
		}
		if err := os.WriteFile(destination, certPEM, 0o644); err != nil {
			return fmt.Errorf("save CA certificate: %w (move Ghost Proxy to a folder you can write to, such as Desktop or Documents)", err)
		}
		caRelative = "server.crt"
		break
	}

	psk := currentPSK
	for {
		prompt := "PSK (hex key from your provider): "
		if psk != "" {
			prompt = "PSK (press Enter to keep the current key): "
		}

		value, err := ui.askSecret(prompt)
		if err != nil {
			return err
		}
		if value == "" {
			if psk != "" {
				break
			}
			fmt.Fprintln(ui.out, "  PSK is required.")
			continue
		}
		if err := validatePSK(value); err != nil {
			fmt.Fprintf(ui.out, "  %v\n", err)
			continue
		}
		psk = value
		break
	}

	cfg := clientConfigFile{
		ListenAddress:  existing.ListenAddress,
		ServerAddress:  serverAddress,
		ServerName:     serverName,
		CAFile:         caRelative,
		LogLevel:       existing.LogLevel,
		PaddingEnabled: existing.PaddingEnabled,
		JitterMS:       existing.JitterMS,
	}
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = defaultListenAddress
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
		return fmt.Errorf("encode configuration: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		return fmt.Errorf("create config directory: %w (move Ghost Proxy to a folder you can write to, such as Desktop or Documents)", err)
	}
	if err := os.WriteFile(cfgPath, configData, 0o644); err != nil {
		return fmt.Errorf("save configuration: %w (move Ghost Proxy to a folder you can write to, such as Desktop or Documents)", err)
	}

	envData := []byte("GHOST_PSK=" + psk + "\n")
	if err := os.MkdirAll(filepath.Dir(envPath), 0o755); err != nil {
		return fmt.Errorf("create settings directory: %w", err)
	}
	if err := os.WriteFile(envPath, envData, 0o600); err != nil {
		return fmt.Errorf("save PSK: %w (move Ghost Proxy to a folder you can write to, such as Desktop or Documents)", err)
	}
	if err := os.Setenv("GHOST_PSK", psk); err != nil {
		return fmt.Errorf("apply PSK: %w", err)
	}

	caDisplay := "system trust store"
	if caRelative != "" {
		caDisplay = filepath.Join(filepath.Dir(cfgPath), caRelative)
	}

	fmt.Fprintln(ui.out)
	fmt.Fprintln(ui.out, "Setup complete.")
	fmt.Fprintf(ui.out, "  Server:      %s\n", serverAddress)
	fmt.Fprintf(ui.out, "  Server name: %s\n", serverName)
	fmt.Fprintf(ui.out, "  CA file:     %s\n", caDisplay)
	fmt.Fprintf(ui.out, "  SOCKS5:      %s\n", cfg.ListenAddress)
	fmt.Fprintf(ui.out, "  Settings:    %s\n", cfgPath)
	fmt.Fprintln(ui.out)

	return nil
}

func normalizeServerAddress(raw string) (address, host string, err error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", "", errors.New("server address is required (example: proxy.example.com:443)")
	}
	if strings.Contains(value, "://") {
		return "", "", errors.New("enter host:port only, without http:// or https://")
	}
	if strings.ContainsAny(value, " \t\r\n/") {
		return "", "", errors.New("server address cannot contain spaces or slashes")
	}

	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		switch {
		case strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]"):
			value += ":" + defaultServerPort
		case strings.Count(value, ":") > 1:
			value = "[" + value + "]:" + defaultServerPort
		case !strings.Contains(value, ":"):
			value += ":" + defaultServerPort
		default:
			return "", "", fmt.Errorf("invalid server address: %v", err)
		}

		host, portText, err = net.SplitHostPort(value)
		if err != nil {
			return "", "", fmt.Errorf("invalid server address: %v", err)
		}
	}
	if host == "" {
		return "", "", errors.New("server address must include a host name or IP")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", "", errors.New("server port must be between 1 and 65535")
	}

	return net.JoinHostPort(host, portText), host, nil
}

func validatePSK(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("PSK is required")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return errors.New("PSK must be hexadecimal (0-9, a-f)")
	}
	if len(decoded)*2 < minPSKHexLength {
		return fmt.Errorf("PSK must be at least %d hexadecimal characters", minPSKHexLength)
	}
	return nil
}

func existingCAPath(cfgPath, caFile string) string {
	if caFile == "" {
		return ""
	}
	if filepath.IsAbs(caFile) {
		if pathExists(caFile) {
			return caFile
		}
		return ""
	}
	candidate := filepath.Join(filepath.Dir(cfgPath), caFile)
	if pathExists(candidate) {
		return candidate
	}
	return ""
}

func expandPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	if !filepath.IsAbs(path) {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return "", fmt.Errorf("resolve certificate path: %w", err)
		}
		path = absolute
	}
	return path, nil
}

func validateCertificatePEM(data []byte) error {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return errors.New("the CA file does not contain a valid PEM certificate")
	}
	return nil
}
