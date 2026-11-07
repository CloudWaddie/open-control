// Package config loads Open Control configuration from YAML + env.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen           string      `yaml:"listen"`             // host:port for UDP53/TCP listeners
	APIListen        string      `yaml:"api_listen"`         // host:port for the REST control plane
	DoTListen        string      `yaml:"dot_listen"`         // host:port for DNS-over-TLS (empty = off)
	DoHListen        string      `yaml:"doh_listen"`         // host:port for DNS-over-HTTPS (empty = off)
	TLSCert          string      `yaml:"tls_cert"`           // PEM certificate chain for DoT/DoH
	TLSKey           string      `yaml:"tls_key"`            // PEM private key for DoT/DoH
	LogRetentionDays int         `yaml:"log_retention_days"` // query-log rows older than this are purged
	LogBuffer        int         `yaml:"log_buffer"`         // events buffered before drops begin
	SyslogAddr       string      `yaml:"syslog_addr"`        // host:port, UDP syslog sink (empty = off)
	WebhookURL       string      `yaml:"webhook_url"`        // POST batches of query-log JSON (empty = off)
	Upstreams        []string    `yaml:"upstreams"`          // plain-DNS upstreams, e.g. 1.1.1.1:53
	SQLitePath       string      `yaml:"sqlite_path"`        // database file
	DataDir          string      `yaml:"data_dir"`           // state dir (blocklists, later)
	Cache            CacheConfig `yaml:"cache"`

	// PlainDNSAllow lists the networks that may use plain DNS (UDP/TCP 53)
	// without matching a specific endpoint. Anyone else is refused, so a server
	// on a public address is not an open resolver. Endpoints with a narrower
	// CIDR than 0.0.0.0/0 are always allowed. Set ["0.0.0.0/0", "::/0"] to
	// deliberately run an open resolver.
	PlainDNSAllow []string `yaml:"plain_dns_allow"`
	// RateLimitQPS caps queries per second per client address (IPv6 grouped
	// by /56). Bursts of twice the rate are allowed. 0 disables the limit.
	RateLimitQPS int `yaml:"rate_limit_qps"`
	// MetricsListen serves Prometheus metrics at /metrics (empty = off). Keep
	// it on a private address; it is unauthenticated.
	MetricsListen string `yaml:"metrics_listen"`
	// LogQueries prints every block/rewrite/redirect decision to stdout. The
	// query log records them either way; this is for debugging.
	LogQueries bool `yaml:"log_queries"`
	// TrustedProxies are reverse proxies whose X-Forwarded-For header is
	// believed for the control API (rate limits, audit). Empty = none.
	TrustedProxies []string `yaml:"trusted_proxies"`

	plainAllow []netip.Prefix
	proxies    []netip.Prefix
}

type CacheConfig struct {
	MaxEntries int    `yaml:"max_entries"`
	MinTTL     uint32 `yaml:"min_ttl"` // seconds, floor applied to cached answers
	MaxTTL     uint32 `yaml:"max_ttl"` // seconds, ceiling applied before caching
}

// PrivateNetworks are loopback, RFC 1918, CGNAT, link-local and ULA ranges:
// the default set of networks allowed to use plain DNS.
var PrivateNetworks = []string{
	"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"100.64.0.0/10", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
}

func Default() Config {
	c := Config{
		Listen:           "127.0.0.1:1053",
		APIListen:        "127.0.0.1:8080",
		LogRetentionDays: 7,
		LogBuffer:        4096,
		Upstreams:        []string{"1.1.1.1:53", "8.8.8.8:53"},
		SQLitePath:       "data/opencontrol.db",
		DataDir:          "data",
		PlainDNSAllow:    PrivateNetworks,
		RateLimitQPS:     100,
		Cache: CacheConfig{
			MaxEntries: 65536,
			MinTTL:     30,
			MaxTTL:     3600,
		},
	}
	_ = c.validate() // parses the default network lists; defaults are valid
	return c
}

// Load builds the config: defaults <- YAML file <- environment overrides.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return nil, err
		}
	}
	str := map[string]*string{
		"OC_LISTEN":         &cfg.Listen,
		"OC_API_LISTEN":     &cfg.APIListen,
		"OC_DOT_LISTEN":     &cfg.DoTListen,
		"OC_DOH_LISTEN":     &cfg.DoHListen,
		"OC_TLS_CERT":       &cfg.TLSCert,
		"OC_TLS_KEY":        &cfg.TLSKey,
		"OC_SYSLOG_ADDR":    &cfg.SyslogAddr,
		"OC_WEBHOOK_URL":    &cfg.WebhookURL,
		"OC_SQLITE_PATH":    &cfg.SQLitePath,
		"OC_DATA_DIR":       &cfg.DataDir,
		"OC_METRICS_LISTEN": &cfg.MetricsListen,
	}
	for k, p := range str {
		if v := os.Getenv(k); v != "" {
			*p = v
		}
	}
	lists := map[string]*[]string{
		"OC_UPSTREAMS":       &cfg.Upstreams,
		"OC_PLAIN_DNS_ALLOW": &cfg.PlainDNSAllow,
		"OC_TRUSTED_PROXIES": &cfg.TrustedProxies,
	}
	for k, p := range lists {
		if v := os.Getenv(k); v != "" {
			*p = splitList(v)
		}
	}
	ints := map[string]*int{
		"OC_LOG_RETENTION_DAYS": &cfg.LogRetentionDays,
		"OC_RATE_LIMIT_QPS":     &cfg.RateLimitQPS,
	}
	for k, p := range ints {
		if v := os.Getenv(k); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("%s must be a non-negative integer, got %q", k, v)
			}
			*p = n
		}
	}
	if v := os.Getenv("OC_LOG_QUERIES"); v != "" {
		cfg.LogQueries = v == "1" || strings.EqualFold(v, "true")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if len(c.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}
	var err error
	if c.plainAllow, err = parsePrefixes("plain_dns_allow", c.PlainDNSAllow); err != nil {
		return err
	}
	if c.proxies, err = parsePrefixes("trusted_proxies", c.TrustedProxies); err != nil {
		return err
	}
	if (c.DoTListen != "" || c.DoHListen != "") && (c.TLSCert == "" || c.TLSKey == "") {
		return fmt.Errorf("dot_listen/doh_listen need tls_cert and tls_key")
	}
	return nil
}

// PlainDNSAllowed reports whether addr may use plain DNS without a specific endpoint.
func (c *Config) PlainDNSAllowed(addr netip.Addr) bool {
	return containsAddr(c.plainAllow, addr)
}

// TrustedProxy reports whether addr is a reverse proxy whose forwarding
// headers are believed.
func (c *Config) TrustedProxy(addr netip.Addr) bool {
	return containsAddr(c.proxies, addr)
}

func containsAddr(list []netip.Prefix, addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range list {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func parsePrefixes(field string, in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return nil, fmt.Errorf("%s: %q is not an IP or CIDR", field, s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
