package proxy

import (
	"io"
	"net"

	"github.com/nikita5120/tcp-proxy/internal/logger"
)

// copyBytes streams bytes from src to dst and logs the byte count.
// It half-closes dst (TCP FIN) when src reaches EOF so the remote side
// knows the stream is done without dropping the reverse direction.
func copyBytes(dst, src net.Conn, id uint64, direction string, l *logger.Logger) {
	n, err := io.Copy(dst, src)
	if err != nil && !isClosedErr(err) {
		l.Warnf("[conn %d] %s copy error: %v", id, direction, err)
	}
	l.Infof("[conn %d] %s  bytes=%d", id, direction, n)

	// Half-close: signal EOF on this direction without killing the full conn.
	if tc, ok := dst.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
}

// isClosedErr returns true for "use of closed network connection" noise.
func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	// stdlib wraps this in an opaque error; string check is the standard approach.
	return err.Error() == "use of closed network connection"
}
