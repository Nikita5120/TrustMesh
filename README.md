# tcp-proxy

A TCP reverse proxy written in Go with TLS termination, per-connection goroutine handling, and HTTP header inspection for flagging suspicious traffic patterns.

Built to understand the fundamentals behind security proxies used in Zero Trust network architectures (like Akamai's Enterprise Threat Protector).

---

## What it does

```
Client (HTTPS) ──► [tcp-proxy] ──► Upstream server (HTTP)
                   TLS termination
                   Header inspection
                   Connection logging
```

- **TLS termination** — accepts TLS 1.2+ connections from clients, forwards plain TCP to the upstream. The proxy holds the certificate; the upstream doesn't need to.
- **Per-connection goroutines** — each connection gets its own goroutine pair (client→upstream, upstream→client). Goroutines are cheap (~4 KB stack); this scales to thousands of concurrent connections.
- **Bidirectional pipe with half-close** — uses `io.Copy` in both directions. When one side closes, it sends a TCP FIN (`CloseWrite`) on that direction without killing the reverse stream.
- **HTTP header inspection** — peeks at the first 4 KB of each connection using `bufio.Reader.Peek()` (non-consuming). Flags known attack signatures: scanner user-agents, path traversal, shell injection patterns.
- **Graceful shutdown** — `signal.NotifyContext` catches SIGINT/SIGTERM; listener closes and a `sync.WaitGroup` waits for all in-flight connections to finish before exit.
- **Structured logging** — timestamped INFO/WARN/ERROR levels, per-connection ID, byte counts, duration. Outputs to stdout or a log file.

---

## Run it

```bash
# Plain TCP mode (no TLS)
go run ./cmd/proxy -listen :8080 -upstream localhost:9090

# TLS termination mode
go run ./cmd/proxy \
  -listen :8443 \
  -upstream localhost:8080 \
  -cert cert.pem \
  -key key.pem

# With HTTP header inspection enabled
go run ./cmd/proxy -listen :8443 -upstream localhost:8080 \
  -cert cert.pem -key key.pem -inspect

# Generate a self-signed cert for local testing
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=localhost"
```

---

## Test it

```bash
# Terminal 1 — start a simple upstream
python3 -m http.server 8080

# Terminal 2 — start the proxy
go run ./cmd/proxy -listen :8443 -upstream localhost:8080 \
  -cert cert.pem -key key.pem -inspect

# Terminal 3 — send a request through the proxy
curl -k https://localhost:8443/

# Simulate a suspicious request (should trigger WARN)
curl -k -A "sqlmap/1.7" https://localhost:8443/
```

Expected log output:
```
INFO  2026/01/15 10:23:01.123456 TLS listener ready on :8443 (min TLS 1.2)
INFO  2026/01/15 10:23:05.234567 [conn 1] accepted from 127.0.0.1:54321
INFO  2026/01/15 10:23:05.235123 [conn 1] HTTP request: GET / HTTP/1.1
WARN  2026/01/15 10:23:05.235200 [conn 1] SUSPICIOUS header pattern="sqlmap"  line="User-Agent: sqlmap/1.7"
INFO  2026/01/15 10:23:05.240000 [conn 1] client→upstream  bytes=102
INFO  2026/01/15 10:23:05.241000 [conn 1] upstream→client  bytes=1024
INFO  2026/01/15 10:23:05.241100 [conn 1] closed  from=127.0.0.1:54321  duration=6ms
```

---

## Project structure

```
tcp-proxy/
├── cmd/proxy/
│   └── main.go          # entry point, CLI flags, signal handling
├── internal/
│   ├── config/
│   │   └── config.go    # runtime config struct
│   ├── logger/
│   │   └── logger.go    # levelled logger (INFO/WARN/ERROR)
│   └── proxy/
│       ├── server.go    # listener, TLS setup, goroutine-per-conn
│       ├── pipe.go      # bidirectional io.Copy with half-close
│       └── inspect.go   # HTTP header inspection, suspicious patterns
└── go.mod
```

---

## Key Go concepts demonstrated

| Concept | Where |
|---|---|
| `net.Listen` / `net.Dial` | `server.go` |
| `crypto/tls` — cert loading, `MinVersion` | `server.go` |
| Goroutines + `sync.WaitGroup` | `server.go`, `pipe.go` |
| `atomic.Uint64` for lock-free counters | `server.go` |
| `bufio.Reader.Peek()` — non-consuming read | `inspect.go` |
| `io.Copy` for zero-allocation stream pipe | `pipe.go` |
| `net.TCPConn.CloseWrite()` — TCP half-close | `pipe.go` |
| `signal.NotifyContext` for graceful shutdown | `main.go` |
| Zero external dependencies | `go.mod` |

---

## Why Zero Trust relevance

A Zero Trust proxy is, at its core, a connection interceptor that:
1. Terminates TLS (so it can inspect traffic)
2. Authenticates/authorizes the connection before forwarding
3. Logs everything for audit

This project implements steps 1 and 3. Step 2 (policy enforcement) is the natural next extension — adding an allowlist of upstream hosts, mTLS client certificate validation, or JWT header verification.

Akamai's Enterprise Threat Protector operates on these same primitives at global scale.
