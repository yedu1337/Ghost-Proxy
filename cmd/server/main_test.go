package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yedukrishna012/ghost-proxy/pkg/gateway"
)

func TestRawHTTPProbeIsRelayedToDecoy(t *testing.T) {
	decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/probe" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "decoy response")
	}))
	defer decoy.Close()
	decoyAddress := strings.TrimPrefix(decoy.URL, "http://")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &gateway.Server{
		Prepare: func(c net.Conn) (net.Conn, error) { return prepareGatewayTLS(c, nil) },
		OnFallback: func(c net.Conn, replay io.Reader) {
			proxyToNginx(c, replay, decoyAddress)
		},
	}
	go func() { _ = srv.Serve(ln) }()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	request := "GET /probe HTTP/1.1\r\nHost: decoy.test\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "decoy response" {
		t.Fatalf("decoy response = %d %q", response.StatusCode, body)
	}
}
