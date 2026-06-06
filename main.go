package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/nikita5120/tcp-proxy/internal/config"
	"github.com/nikita5120/tcp-proxy/internal/logger"
	"github.com/nikita5120/tcp-proxy/internal/proxy"
)

func main() {
	// --- CLI flags ---
	listenAddr  := flag.String("listen", ":8443", "Address to listen on (e.g. :8443)")
	upstreamAddr := flag.String("upstream", "localhost:8080", "Upstream server to forward to")
	tlsCert     := flag.String("cert", "", "Path to TLS certificate (PEM). Omit for plain TCP mode.")
	tlsKey      := flag.String("key", "", "Path to TLS private key (PEM). Omit for plain TCP mode.")
	logFile     := flag.String("logfile", "", "Path to log file. Defaults to stdout.")
	inspect     := flag.Bool("inspect", false, "Enable HTTP header inspection for suspicious patterns")
	flag.Parse()

	// --- Logger setup ---
	l := logger.New(*logFile)
	l.Info("tcp-proxy starting")
	l.Infof("listen=%s  upstream=%s  tls=%v  inspect=%v",
		*listenAddr, *upstreamAddr, *tlsCert != "", *inspect)

	// --- Config ---
	cfg := &config.Config{
		ListenAddr:   *listenAddr,
		UpstreamAddr: *upstreamAddr,
		TLSCertFile:  *tlsCert,
		TLSKeyFile:   *tlsKey,
		Inspect:      *inspect,
	}

	// --- Proxy server ---
	srv, err := proxy.New(cfg, l)
	if err != nil {
		l.Fatalf("failed to create proxy: %v", err)
	}

	// --- Graceful shutdown via OS signals ---
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := srv.Start(); err != nil {
			l.Fatalf("proxy error: %v", err)
		}
	}()

	<-ctx.Done()
	l.Info("shutdown signal received — draining connections...")
	srv.Shutdown()
	l.Info("proxy stopped cleanly")
}
