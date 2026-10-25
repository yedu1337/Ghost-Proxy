package transport

import (
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	ExporterLabel  = "ghost-proxy"
	ExporterLength = 32
)

// TLSConfig returns the TLS 1.3 configuration used by Ghost Proxy.
func TLSConfig(serverName string) *utls.Config {
	return &utls.Config{
		ServerName:    serverName,
		MinVersion:    utls.VersionTLS13,
		MaxVersion:    utls.VersionTLS13,
		Renegotiation: utls.RenegotiateNever,
		NextProtos:    []string{"http/1.1"},
		VerifyConnection: func(state utls.ConnectionState) error {
			if state.Version != utls.VersionTLS13 {
				return fmt.Errorf(
					"ghost-proxy: expected TLS 1.3, negotiated %s",
					utls.VersionName(state.Version),
				)
			}
			return nil
		},
	}
}
func TLSConfigWithRootCA(serverName, certFile string) (*utls.Config, error) {
	config := TLSConfig(serverName)
	if certFile == "" {
		return config, nil
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("ghost-proxy: read CA certificate: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		return nil, fmt.Errorf("ghost-proxy: parse CA certificate")
	}

	config.RootCAs = pool
	return config, nil
}

// DialUTLS establishes a TLS 1.3 connection using a controlled
// Chrome-style ClientHello profile.
func DialUTLS(rawConn net.Conn, serverName string) (*utls.UConn, error) {
	return dialUTLS(rawConn, TLSConfig(serverName))
}

// DialUTLSWithConfig establishes a TLS 1.3 connection using the supplied configuration.
func DialUTLSWithConfig(rawConn net.Conn, config *utls.Config) (*utls.UConn, error) {
	return dialUTLS(rawConn, config)
}

// dialUTLS performs the uTLS connection setup using the supplied
// configuration. This allows tests to provide their own trusted
// certificate pool without disabling certificate verification.
func dialUTLS(
	rawConn net.Conn,
	config *utls.Config,
) (*utls.UConn, error) {
	if rawConn == nil {
		return nil, fmt.Errorf("ghost-proxy: nil underlying connection")
	}

	if config == nil {
		rawConn.Close()
		return nil, fmt.Errorf("ghost-proxy: nil TLS config")
	}

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf(
			"ghost-proxy: build Chrome ClientHello profile: %w",
			err,
		)
	}

	// Remove the renegotiation extension because uTLS v1.8.2
	// propagates its renegotiation mode into Config.Renegotiation,
	// which disables TLS exporter access.
	spec.Extensions = removeRenegotiationExtension(spec.Extensions)

	conn := utls.UClient(
		rawConn,
		config,
		utls.HelloCustom,
	)

	if err := conn.ApplyPreset(&spec); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf(
			"ghost-proxy: apply Chrome ClientHello profile: %w",
			err,
		)
	}

	_ = rawConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf(
			"ghost-proxy: TLS handshake: %w",
			err,
		)
	}
	_ = conn.SetDeadline(time.Time{})

	state := conn.ConnectionState()

	if state.Version != utls.VersionTLS13 {
		conn.Close()
		return nil, fmt.Errorf(
			"ghost-proxy: negotiated %s instead of TLS 1.3",
			utls.VersionName(state.Version),
		)
	}

	return conn, nil
}

// removeRenegotiationExtension removes the renegotiation extension
// from a copied ClientHello profile.
func removeRenegotiationExtension(
	extensions []utls.TLSExtension,
) []utls.TLSExtension {
	filtered := make([]utls.TLSExtension, 0, len(extensions))

	for _, ext := range extensions {
		if _, ok := ext.(*utls.RenegotiationInfoExtension); ok {
			continue
		}

		filtered = append(filtered, ext)
	}

	return filtered
}

// ExportKeyingMaterial extracts TLS exporter material from an
// established uTLS connection.
func ExportKeyingMaterial(conn *utls.UConn) ([]byte, error) {
	if conn == nil {
		return nil, fmt.Errorf("ghost-proxy: nil TLS connection")
	}

	state := conn.ConnectionState()

	material, err := state.ExportKeyingMaterial(
		ExporterLabel,
		nil,
		ExporterLength,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"ghost-proxy: export keying material: %w",
			err,
		)
	}

	return material, nil
}

// VerifyTLS13Connection performs a controlled post-handshake
// verification of the negotiated TLS version.
func VerifyTLS13Connection(conn net.Conn) error {
	if conn == nil {
		return fmt.Errorf("ghost-proxy: nil connection")
	}

	uconn, ok := conn.(*utls.UConn)
	if !ok {
		return fmt.Errorf(
			"ghost-proxy: expected uTLS connection, got %T",
			conn,
		)
	}

	state := uconn.ConnectionState()

	if state.Version != utls.VersionTLS13 {
		return fmt.Errorf(
			"ghost-proxy: expected TLS 1.3, negotiated %s",
			utls.VersionName(state.Version),
		)
	}

	return nil
}

// Ensure the uTLS connection remains compatible with net.Conn.
var _ net.Conn = (*utls.UConn)(nil)
