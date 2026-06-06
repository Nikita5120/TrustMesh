package proxy

import (
	"bufio"
	"bytes"
	"net"
	"strings"

	"github.com/nikita5120/tcp-proxy/internal/logger"
)

// suspiciousPatterns are HTTP header values that warrant a warning.
// In a real Zero Trust proxy you'd feed these into a policy engine.
var suspiciousPatterns = []string{
	"sqlmap",          // automated SQL injection tool
	"nikto",           // web vulnerability scanner
	"masscan",         // port scanner UA
	"zgrab",           // banner grabber
	"curl/7.1",        // very old curl — often scripted attacks
	"python-requests", // generic scripted HTTP client
	"<script",         // XSS attempt in headers
	"../",             // path traversal
	"passwd",          // /etc/passwd fishing
	"cmd.exe",         // Windows shell injection
}

// inspectConn wraps a net.Conn and peeks at the first 4 KB for HTTP patterns.
// After inspection the bytes are buffered back so the upstream sees them intact.
type inspectConn struct {
	net.Conn
	reader *bufio.Reader
}

func newInspectConn(c net.Conn, id uint64, l *logger.Logger) net.Conn {
	br := bufio.NewReaderSize(c, 4096)

	// Peek — does NOT consume the bytes; they remain readable via br.
	peek, err := br.Peek(4096)
	if err != nil && len(peek) == 0 {
		// Nothing to inspect yet (e.g. non-HTTP, or connection closed early).
		return c
	}

	inspectHeaders(peek, id, l)

	return &inspectConn{Conn: c, reader: br}
}

// Read satisfies net.Conn by draining the buffered reader first.
func (ic *inspectConn) Read(b []byte) (int, error) {
	return ic.reader.Read(b)
}

// inspectHeaders scans raw bytes for HTTP request line + headers.
func inspectHeaders(data []byte, id uint64, l *logger.Logger) {
	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		s := strings.ToLower(string(line))
		for _, pat := range suspiciousPatterns {
			if strings.Contains(s, pat) {
				l.Warnf("[conn %d] SUSPICIOUS header pattern=%q  line=%q", id, pat, strings.TrimSpace(string(line)))
			}
		}

		// Log the HTTP method + path from the request line (first line).
		// Format: METHOD /path HTTP/1.x
		if bytes.HasPrefix(line, []byte("GET ")) ||
			bytes.HasPrefix(line, []byte("POST ")) ||
			bytes.HasPrefix(line, []byte("PUT ")) ||
			bytes.HasPrefix(line, []byte("DELETE ")) ||
			bytes.HasPrefix(line, []byte("CONNECT ")) {
			l.Infof("[conn %d] HTTP request: %s", id, strings.TrimSpace(string(line)))
		}
	}
}
