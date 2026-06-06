package config

// Config holds all runtime configuration for the proxy.
type Config struct {
	ListenAddr   string // e.g. ":8443"
	UpstreamAddr string // e.g. "localhost:8080"
	TLSCertFile  string // path to PEM cert; empty = plain TCP
	TLSKeyFile   string // path to PEM key;  empty = plain TCP
	Inspect      bool   // enable HTTP header inspection
}

// TLSEnabled returns true when both cert and key are provided.
func (c *Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}
