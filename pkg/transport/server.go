package transport

import (
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"
)

// TLSServerConfig returns the TLS 1.3 configuration used by the
// Ghost Proxy gateway.
func TLSServerConfig(certFile, keyFile string) (*utls.Config, error) {
	if certFile == "" {
		return nil, fmt.Errorf("ghost-proxy: TLS certificate file is required")
	}

	if keyFile == "" {
		return nil, fmt.Errorf("ghost-proxy: TLS private key file is required")
	}

	cert, err := utls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("ghost-proxy: load TLS certificate: %w", err)
	}

	return &utls.Config{
		Certificates:  []utls.Certificate{cert},
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
	}, nil
}

// TLSServer wraps an accepted TCP connection in a TLS 1.3 server
// connection and completes the TLS handshake.
func TLSServer(rawConn net.Conn, config *utls.Config) (*utls.Conn, error) {
	if rawConn == nil {
		return nil, fmt.Errorf("ghost-proxy: nil underlying connection")
	}

	if config == nil {
		rawConn.Close()
		return nil, fmt.Errorf("ghost-proxy: nil TLS server config")
	}

	conn := utls.Server(rawConn, config)

	if err := conn.Handshake(); err != nil {
		return nil, fmt.Errorf(
			"ghost-proxy: TLS server handshake: %w",
			err,
		)
	}

	state := conn.ConnectionState()

	if state.Version != utls.VersionTLS13 {
		return nil, fmt.Errorf(
			"ghost-proxy: negotiated %s instead of TLS 1.3",
			utls.VersionName(state.Version),
		)
	}

	return conn, nil
}

// ExportServerKeyingMaterial extracts the TLS exporter material from
// an established TLS server connection.
func ExportServerKeyingMaterial(conn *utls.Conn) ([]byte, error) {
	if conn == nil {
		return nil, fmt.Errorf("ghost-proxy: nil TLS server connection")
	}

	state := conn.ConnectionState()

	if state.Version != utls.VersionTLS13 {
		return nil, fmt.Errorf(
			"ghost-proxy: expected TLS 1.3, negotiated %s",
			utls.VersionName(state.Version),
		)
	}

	material, err := state.ExportKeyingMaterial(
		ExporterLabel,
		nil,
		ExporterLength,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"ghost-proxy: export server keying material: %w",
			err,
		)
	}

	return material, nil
}

// Ensure the TLS server connection remains compatible with net.Conn.
var _ net.Conn = (*utls.Conn)(nil)
