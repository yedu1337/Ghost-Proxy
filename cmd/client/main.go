package main

import (
	"flag"
	"log"
	"net"
	"path/filepath"

	"github.com/yedukrishna012/ghost-proxy/pkg/client"
	"github.com/yedukrishna012/ghost-proxy/pkg/config"
	"github.com/yedukrishna012/ghost-proxy/pkg/logger"
	"github.com/yedukrishna012/ghost-proxy/pkg/socks5"
)

func main() {
	configPath := flag.String("config", "configs/client.yaml", "client config path")
	flag.Parse()
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	configAbs, err := filepath.Abs(*configPath)
	if err != nil {
		log.Fatalf("resolve config path: %v", err)
	}
	if cfg.CAFile != "" && !filepath.IsAbs(cfg.CAFile) {
		cfg.CAFile = filepath.Join(filepath.Dir(configAbs), cfg.CAFile)
	}
	logger.SetLevel(cfg.LogLevel)
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = "127.0.0.1:1080"
	}
	if host, _, err := net.SplitHostPort(cfg.ListenAddress); err != nil || (!cfg.AllowRemoteBind && host != "127.0.0.1" && host != "::1" && host != "localhost") {
		log.Fatalf("refusing non-loopback SOCKS bind %q", cfg.ListenAddress)
	}
	if cfg.ServerAddress == "" || cfg.ServerName == "" {
		log.Fatal("server_address and server_name must be configured")
	}

	ghostClient, err := client.FromEnvironment(cfg.ServerAddress, cfg.ServerName)
	if err != nil {
		log.Fatalf("create Ghost client: %v", err)
	}
	ghostClient.CAFile = cfg.CAFile
	ghostClient.PaddingEnabled = cfg.PaddingEnabled
	ghostClient.JitterMS = cfg.JitterMS

	server := &socks5.Server{
		Addr: cfg.ListenAddress,
		Dial: ghostClient.Dial,
	}

	if err := server.Start(); err != nil {
		log.Fatalf("SOCKS5 server stopped: %v", err)
	}
}
