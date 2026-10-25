package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/term"

	utls "github.com/refraction-networking/utls"

	"github.com/yedukrishna012/ghost-proxy/pkg/config"
	"github.com/yedukrishna012/ghost-proxy/pkg/gateway"
	"github.com/yedukrishna012/ghost-proxy/pkg/logger"
	"github.com/yedukrishna012/ghost-proxy/pkg/transport"
)

const minPSKLen = 16

func exportServerKeyingMaterial(conn net.Conn) ([]byte, error) {
	tlsConn, ok := conn.(*utls.Conn)
	if !ok {
		return nil, fmt.Errorf(
			"ghost-proxy: expected TLS connection, got %T",
			conn,
		)
	}

	return transport.ExportServerKeyingMaterial(tlsConn)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Ghost Proxy server error:", err)
		if isInteractive() {
			fmt.Fprintln(os.Stderr, "\nPress Enter to close...")
			_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		}
		os.Exit(1)
	}
}

func isInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

func run(args []string) error {
	flags := flag.NewFlagSet("GhostProxyServer", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	configFlag := flags.String("config", "configs/server.yaml", "path to the server configuration file")
	envFlag := flags.String("env-file", "ghost.env", "path to the GHOST_PSK environment file")
	listen := flags.String("listen", "", "override the listen address from the config")
	setupFlag := flags.Bool("setup", false, "run the setup wizard, then start the gateway")
	setupOnly := flags.Bool("setup-only", false, "run the setup wizard and exit")
	checkFlag := flags.Bool("check", false, "validate the configuration and exit")
	showInvite := flags.Bool("show-invite", false, "print the details to send to users and exit")
	publicHost := flags.String("public-host", "", "public host name or IP used by clients")
	publicPort := flags.Int("public-port", 0, "public TCP port used by clients")
	certFile := flags.String("cert-file", "", "TLS certificate chain path")
	keyFile := flags.String("key-file", "", "TLS private key path")
	selfSigned := flags.Bool("self-signed", false, "generate a self-signed certificate during setup")
	fallback := flags.String("fallback-address", "", "fallback HTTP decoy address (host:port or none)")
	allowed := flags.String("allowed-destinations", "", "comma-separated allowed hosts or CIDRs (blank = all public destinations)")
	psk := flags.String("psk", "", "PSK in hexadecimal (blank = keep existing or generate)")
	forcePSK := flags.Bool("force-psk", false, "generate a new PSK during setup instead of keeping the existing one")
	force := flags.Bool("force", false, "replace existing certificate files during setup")
	nonInteractive := flags.Bool("non-interactive", false, "never prompt; use flags and defaults")
	inviteFile := flags.String("invite-file", "", "write the user invite text to this file")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	configPath, err := filepath.Abs(*configFlag)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	envPath, err := filepath.Abs(*envFlag)
	if err != nil {
		return fmt.Errorf("resolve env path: %w", err)
	}

	if err := loadServerEnvFile(envPath); err != nil {
		return fmt.Errorf("read %s: %w", envPath, err)
	}

	_, configErr := config.Load(configPath)
	configExists := configErr == nil
	if configErr != nil && !errors.Is(configErr, os.ErrNotExist) {
		return configErr
	}

	setupRequested := *setupFlag || *setupOnly
	pskMissing := os.Getenv("GHOST_PSK") == ""
	needsSetup := setupRequested

	if !needsSetup {
		switch {
		case !configExists:
			if isInteractive() && !*checkFlag && !*showInvite {
				needsSetup = true
			} else {
				return fmt.Errorf("no usable configuration found at %s; run with --setup", configPath)
			}
		case pskMissing:
			if isInteractive() && !*checkFlag && !*showInvite {
				needsSetup = true
			} else {
				return fmt.Errorf("GHOST_PSK is not set; add it to %s or run with --setup", envPath)
			}
		}
	}

	if needsSetup {
		opts := serverSetupOptions{
			ConfigPath:     configPath,
			EnvPath:        envPath,
			PublicHost:     *publicHost,
			Port:           *publicPort,
			CertFile:       *certFile,
			KeyFile:        *keyFile,
			Fallback:       *fallback,
			Allowed:        *allowed,
			PSK:            *psk,
			ForcePSK:       *forcePSK,
			SelfSigned:     *selfSigned,
			Force:          *force,
			NonInteractive: *nonInteractive,
			InviteFile:     *inviteFile,
		}
		result, err := runServerSetup(opts, newServerSetupUI(os.Stdin, os.Stdout))
		if err != nil {
			return err
		}
		if *setupOnly {
			fmt.Println()
			fmt.Println("Settings saved. Start the gateway with the same command without --setup-only.")
			return nil
		}
		fmt.Println()
		fmt.Printf("Starting the gateway on %s.\n", result.Config.ListenAddress)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	if *showInvite {
		return printServerInvite(cfg, os.Stdout)
	}

	if *listen != "" {
		cfg.ListenAddress = *listen
	}

	if *checkFlag {
		return checkServerConfiguration(cfg, configPath, envPath, os.Stdout)
	}

	// Validate before starting so service managers show a clear error instead
	// of a partial startup.
	if err := checkServerConfiguration(cfg, configPath, envPath, io.Discard); err != nil {
		return err
	}

	logger.SetLevel(cfg.LogLevel)

	pskHex := os.Getenv("GHOST_PSK")
	pskBytes, err := hex.DecodeString(pskHex)
	if err != nil {
		return fmt.Errorf("decode GHOST_PSK: %w", err)
	}

	if len(pskBytes) < minPSKLen {
		return fmt.Errorf("GHOST_PSK must decode to at least %d bytes", minPSKLen)
	}

	tlsConfig, err := transport.TLSServerConfig(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return err
	}

	rawLn, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return err
	}

	ln := rawLn

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var profileServer *http.Server
	if cfg.PprofAddress != "" {
		profileServer = &http.Server{
			Addr:              cfg.PprofAddress,
			Handler:           http.DefaultServeMux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			logger.Info("pprof listening", "addr", cfg.PprofAddress)
			if err := profileServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("pprof server stopped", "err", err)
				stop()
			}
		}()
	}

	go func() {
		<-ctx.Done()
		logger.Info("shutting down")
		ln.Close()
		if profileServer != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := profileServer.Shutdown(shutdownCtx); err != nil {
				logger.Warn("pprof shutdown failed", "err", err)
			}
		}
	}()

	srv := &gateway.Server{
		PSK:      []byte(pskBytes),
		Exporter: exportServerKeyingMaterial,
		Prepare: func(raw net.Conn) (net.Conn, error) {
			return prepareGatewayTLS(raw, tlsConfig)
		},
		OnFallback: func(conn net.Conn, replay io.Reader) { proxyToNginx(conn, replay, cfg.FallbackAddress) },
		OnAuthenticated: func(conn net.Conn, session *gateway.AuthSession) {
			defer conn.Close()

			targetInfo := "authenticated connection"
			if remote := conn.RemoteAddr(); remote != nil {
				targetInfo += " remote=" + remote.String()
			}

			logger.Info(targetInfo)

			if err := gateway.ServeTunnelWithOptions(conn, session, gateway.TunnelOptions{AllowedDestinations: cfg.AllowedDestinations, PaddingEnabled: cfg.PaddingEnabled, JitterMS: cfg.JitterMS}); err != nil {
				target := conn.RemoteAddr()
				if target != nil {
					logger.Warn(
						"tunnel ended",
						"remote",
						target.String(),
						"error",
						err,
					)
				} else {
					logger.Warn("tunnel ended", "error", err)
				}
			}
		},
	}

	logger.Info("gateway listening", "addr", ln.Addr().String())
	return srv.Serve(ln)
}

// prepareGatewayTLS avoids sending a TLS alert to plain HTTP probes. The
// buffered reader is shared with the TLS layer so its peeked ClientHello byte
// remains available to the handshake. Failed handshakes still cannot be
// transparently continued through the plain HTTP decoy.
func prepareGatewayTLS(raw net.Conn, tlsConfig *utls.Config) (net.Conn, error) {
	if err := raw.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, fmt.Errorf("set TLS handshake deadline: %w", err)
	}
	reader := bufio.NewReader(raw)
	first, err := reader.Peek(1)
	if err != nil {
		return nil, fmt.Errorf("read connection preface: %w", err)
	}
	if first[0] != 0x16 {
		return nil, fmt.Errorf("connection does not begin with a TLS handshake record")
	}
	tlsConn, err := transport.TLSServer(&bufferedConn{Conn: raw, reader: reader}, tlsConfig)
	if err != nil {
		return nil, err
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("clear TLS handshake deadline: %w", err)
	}
	return tlsConn, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func proxyToNginx(client net.Conn, replay io.Reader, addr string) {
	if addr == "" {
		_ = client.Close()
		return
	}
	upstream, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		_ = client.Close()
		return
	}
	defer upstream.Close()
	defer client.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, copyErr := relayCopy(upstream, replay, client, 5*time.Minute)
		if copyErr != nil {
			_ = client.Close()
			_ = upstream.Close()
		}
		if c, ok := upstream.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, copyErr := relayCopy(client, upstream, upstream, 5*time.Minute)
		if copyErr != nil {
			_ = client.Close()
			_ = upstream.Close()
		}
		if c, ok := client.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

func relayCopy(dst net.Conn, src io.Reader, readConn net.Conn, idle time.Duration) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		_ = readConn.SetReadDeadline(time.Now().Add(idle))
		n, rerr := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(idle))
			if werr := writeFallbackAll(dst, buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if rerr != nil {
			if rerr == io.EOF {
				return total, nil
			}
			return total, rerr
		}
	}
}

func writeFallbackAll(dst net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := dst.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
