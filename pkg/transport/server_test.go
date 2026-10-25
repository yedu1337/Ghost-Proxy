package transport

import (
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestTLSServerExporterMatchesClient(t *testing.T) {
	cert, pool := testCertificate(t)

	serverConn, clientConn := net.Pipe()

	serverConfig := &utls.Config{
		Certificates:  []utls.Certificate{cert},
		MinVersion:    utls.VersionTLS13,
		MaxVersion:    utls.VersionTLS13,
		Renegotiation: utls.RenegotiateNever,
	}

	clientConfig := TLSConfig("localhost")
	clientConfig.RootCAs = pool

	serverExporter := make(chan []byte, 1)
	serverErr := make(chan error, 1)

	go func() {
		serverTLS, err := TLSServer(serverConn, serverConfig)
		if err != nil {
			serverErr <- err
			return
		}
		defer serverTLS.Close()

		exporter, err := ExportServerKeyingMaterial(serverTLS)
		if err != nil {
			serverErr <- err
			return
		}

		serverExporter <- exporter
		serverErr <- nil
	}()

	clientTLS, err := dialUTLS(clientConn, clientConfig)
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	defer clientTLS.Close()

	if err := <-serverErr; err != nil {
		t.Fatalf("server TLS/exporter failed: %v", err)
	}

	clientExporter, err := ExportKeyingMaterial(clientTLS)
	if err != nil {
		t.Fatalf("client exporter failed: %v", err)
	}

	serverExporterValue := <-serverExporter

	if len(serverExporterValue) != ExporterLength {
		t.Fatalf(
			"server exporter length = %d, want %d",
			len(serverExporterValue),
			ExporterLength,
		)
	}

	if len(clientExporter) != ExporterLength {
		t.Fatalf(
			"client exporter length = %d, want %d",
			len(clientExporter),
			ExporterLength,
		)
	}

	if string(clientExporter) != string(serverExporterValue) {
		t.Fatal("client and server TLS exporter material does not match")
	}

	if state := clientTLS.ConnectionState(); state.Version != utls.VersionTLS13 {
		t.Fatalf(
			"client negotiated %s, want TLS 1.3",
			utls.VersionName(state.Version),
		)
	}
}
