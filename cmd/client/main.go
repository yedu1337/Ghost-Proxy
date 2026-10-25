package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/yedukrishna012/ghost-proxy/pkg/client"
	"github.com/yedukrishna012/ghost-proxy/pkg/config"
	"github.com/yedukrishna012/ghost-proxy/pkg/logger"
	"github.com/yedukrishna012/ghost-proxy/pkg/socks5"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "\nGhost Proxy error:", err)
		if isInteractive() {
			fmt.Fprintln(os.Stderr, "\nPress Enter to close...")
			_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		}
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("GhostProxy", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configFlag := flags.String("config", "", "path to the client configuration file")
	envFlag := flags.String("env", "", "path to the ghost.env file")
	setupFlag := flags.Bool("setup", false, "run the setup wizard, then start the client")
	setupOnly := flags.Bool("setup-only", false, "run the setup wizard and exit")
	checkFlag := flags.Bool("check", false, "verify the configuration and gateway connection, then exit")
	checkTarget := flags.String("check-target", "example.com:80", "HTTP destination used by --check")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	baseDir := resolveBaseDir()
	configPath := *configFlag
	if configPath == "" {
		configPath = filepath.Join(baseDir, "configs", "client.yaml")
	} else if !filepath.IsAbs(configPath) {
		absolute, err := filepath.Abs(configPath)
		if err != nil {
			return fmt.Errorf("resolve config path: %w", err)
		}
		configPath = absolute
	}

	envPath := *envFlag
	if envPath == "" {
		envPath = filepath.Join(baseDir, "ghost.env")
	} else if !filepath.IsAbs(envPath) {
		absolute, err := filepath.Abs(envPath)
		if err != nil {
			return fmt.Errorf("resolve env path: %w", err)
		}
		envPath = absolute
	}

	if err := loadEnvFile(envPath); err != nil {
		return fmt.Errorf("read %s: %w", envPath, err)
	}

	_, configErr := config.Load(configPath)
	needsSetup := *setupFlag || *setupOnly || configErr != nil || os.Getenv("GHOST_PSK") == ""
	if needsSetup {
		if !*setupFlag && !*setupOnly && !isInteractive() {
			return fmt.Errorf("no usable configuration found; run with --setup")
		}
		if err := runSetup(configPath, envPath, newSetupUI(os.Stdin, os.Stdout)); err != nil {
			return err
		}
		if *setupOnly {
			fmt.Println("\nSettings saved. Run Ghost Proxy again to start.")
			return nil
		}
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	configAbsolute, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	if cfg.CAFile != "" && !filepath.IsAbs(cfg.CAFile) {
		cfg.CAFile = filepath.Join(filepath.Dir(configAbsolute), cfg.CAFile)
	}
	logger.SetLevel(cfg.LogLevel)
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = "127.0.0.1:1080"
	}
	if host, _, err := net.SplitHostPort(cfg.ListenAddress); err != nil || (!cfg.AllowRemoteBind && host != "127.0.0.1" && host != "::1" && host != "localhost") {
		return fmt.Errorf("refusing non-loopback SOCKS bind %q", cfg.ListenAddress)
	}
	if cfg.ServerAddress == "" || cfg.ServerName == "" {
		return fmt.Errorf("server_address and server_name must be configured")
	}

	ghostClient, err := client.FromEnvironment(cfg.ServerAddress, cfg.ServerName)
	if err != nil {
		return fmt.Errorf("create Ghost client: %w", err)
	}
	ghostClient.CAFile = cfg.CAFile
	ghostClient.PaddingEnabled = cfg.PaddingEnabled
	ghostClient.JitterMS = cfg.JitterMS

	if *checkFlag {
		return runClientCheck(ghostClient, cfg, *checkTarget)
	}

	server := &socks5.Server{
		Addr: cfg.ListenAddress,
		Dial: ghostClient.Dial,
	}

	fmt.Println()
	fmt.Println("Ghost Proxy is running.")
	fmt.Println()
	fmt.Printf("  SOCKS5 proxy: %s\n", cfg.ListenAddress)
	fmt.Println("  In your browser or app, choose SOCKS5 host 127.0.0.1 and port 1080.")
	fmt.Println("  Keep this window open. Press Ctrl+C to stop.")
	fmt.Println()
	fmt.Println("  To change the server address, PSK, or certificate, run GhostProxy Settings.")
	fmt.Println()

	if err := server.Start(); err != nil {
		return fmt.Errorf("SOCKS5 server stopped: %w", err)
	}
	return nil
}

func runClientCheck(ghostClient *client.Client, cfg config.Config, target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		target = "example.com:80"
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("invalid --check-target %q: use host:port, for example example.com:80", target)
	}

	fmt.Println()
	fmt.Println("Checking Ghost Proxy...")
	fmt.Printf("  Server:      %s\n", cfg.ServerAddress)
	fmt.Printf("  Server name: %s\n", cfg.ServerName)
	fmt.Printf("  Test target: %s\n", target)
	fmt.Println()

	transport := &http.Transport{
		DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			return ghostClient.Dial(address)
		},
		DisableKeepAlives: true,
		ForceAttemptHTTP2: false,
	}
	defer transport.CloseIdleConnections()

	httpClient := &http.Client{Transport: transport, Timeout: 25 * time.Second}
	resp, err := httpClient.Get("http://" + target + "/")
	if err != nil {
		if hint := clientCheckHint(err); hint != "" {
			return fmt.Errorf("connection check failed: %w\n\n%s", err, hint)
		}
		return fmt.Errorf("connection check failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	fmt.Printf("  Test request: HTTP %s\n", resp.Status)
	fmt.Println("Connection works.")
	return nil
}

func clientCheckHint(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "authenticate"):
		return "The PSK does not match the gateway. Ask the operator for the current key."
	case strings.Contains(message, "certificate") || strings.Contains(message, "x509"):
		return "The TLS certificate could not be verified. Check the server address, server name, and CA certificate."
	case strings.Contains(message, "no such host"):
		return "The server address could not be resolved. Check the spelling and your internet connection."
	case strings.Contains(message, "timeout") || strings.Contains(message, "deadline exceeded"):
		return "The gateway did not respond in time. Check the server address and that TCP 443 is open in the firewall and cloud security group."
	case strings.Contains(message, "connect to ghost server") || strings.Contains(message, "connection refused") || strings.Contains(message, "connection reset"):
		return "The gateway could not be reached. Check the server address and that TCP 443 is open in the firewall and cloud security group."
	case strings.Contains(message, "destination") || strings.Contains(message, "not allowed"):
		return "The gateway refused the test destination. If it has an allowed_destinations list, use --check-target with an allowed HTTP host:port."
	default:
		return ""
	}
}

func isInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

func resolveBaseDir() string {
	if cwd, err := os.Getwd(); err == nil {
		if pathExists(filepath.Join(cwd, "configs", "client.yaml")) || pathExists(filepath.Join(cwd, "ghost.env")) {
			return cwd
		}
	}

	if executable, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(executable); err == nil {
			executable = resolved
		}
		return filepath.Dir(executable)
	}

	cwd, _ := os.Getwd()
	return cwd
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// loadEnvFile reads GHOST_PSK from a simple KEY=VALUE file. Values already
// present in the environment take precedence.
func loadEnvFile(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(key) != "GHOST_PSK" {
			continue
		}
		if os.Getenv("GHOST_PSK") == "" {
			value = strings.Trim(strings.TrimSpace(value), `"'`)
			if err := os.Setenv("GHOST_PSK", value); err != nil {
				return err
			}
		}
	}
	return nil
}
