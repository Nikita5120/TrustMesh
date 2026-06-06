package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nikita5120/tcp-proxy/internal/config"
	"github.com/nikita5120/tcp-proxy/internal/logger"
)

// Server is the TCP reverse proxy.
type Server struct {
	cfg      *config.Config
	log      *logger.Logger
	listener net.Listener
	wg       sync.WaitGroup       // tracks live connections
	connID   atomic.Uint64        // monotonic connection counter
	quit     chan struct{}
}

// New creates a Server and binds the listener (plain TCP or TLS).
func New(cfg *config.Config, l *logger.Logger) (*Server, error) {
	s := &Server{cfg: cfg, log: l, quit: make(chan struct{})}

	var ln net.Listener
	var err error

	if cfg.TLSEnabled() {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS keypair: %w", err)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			// Enforce TLS 1.2+ — no legacy negotiation
			MinVersion: tls.VersionTLS12,
		}
		ln, err = tls.Listen("tcp", cfg.ListenAddr, tlsCfg)
		if err != nil {
			return nil, fmt.Errorf("tls listen: %w", err)
		}
		l.Infof("TLS listener ready on %s (min TLS 1.2)", cfg.ListenAddr)
	} else {
		ln, err = net.Listen("tcp", cfg.ListenAddr)
		if err != nil {
			return nil, fmt.Errorf("tcp listen: %w", err)
		}
		l.Infof("plain TCP listener ready on %s", cfg.ListenAddr)
	}

	s.listener = ln
	return s, nil
}

// Start accepts connections in a loop. Blocks until the listener is closed.
func (s *Server) Start() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return nil // clean shutdown
			default:
				return fmt.Errorf("accept: %w", err)
			}
		}

		id := s.connID.Add(1)
		s.wg.Add(1)
		// One goroutine per connection — idiomatic Go concurrency.
		go s.handleConn(id, conn)
	}
}

// Shutdown closes the listener and waits for in-flight connections to finish.
func (s *Server) Shutdown() {
	close(s.quit)
	s.listener.Close()
	s.wg.Wait()
}

// handleConn dials the upstream and pipes bytes bidirectionally.
func (s *Server) handleConn(id uint64, client net.Conn) {
	defer s.wg.Done()
	defer client.Close()

	remote := client.RemoteAddr().String()
	s.log.Infof("[conn %d] accepted from %s", id, remote)
	start := time.Now()

	// Dial upstream with a reasonable connect timeout.
	upstream, err := net.DialTimeout("tcp", s.cfg.UpstreamAddr, 5*time.Second)
	if err != nil {
		s.log.Errorf("[conn %d] upstream dial failed: %v", id, err)
		return
	}
	defer upstream.Close()

	// Optional: peek at the first bytes for HTTP header inspection.
	if s.cfg.Inspect {
		client = newInspectConn(client, id, s.log)
	}

	// Bidirectional pipe using two goroutines + a WaitGroup.
	var pipe sync.WaitGroup
	pipe.Add(2)

	go func() {
		defer pipe.Done()
		copyBytes(upstream, client, id, "client→upstream", s.log)
	}()
	go func() {
		defer pipe.Done()
		copyBytes(client, upstream, id, "upstream→client", s.log)
	}()

	pipe.Wait()
	s.log.Infof("[conn %d] closed  from=%s  duration=%s", id, remote, time.Since(start).Round(time.Millisecond))
}
