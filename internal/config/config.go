// Package config loads Open Control configuration from YAML + env.
package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen      string      `yaml:"listen"`       // host:port for UDP53/TCP listeners
	APIListen   string      `yaml:"api_listen"`   // host:port for the REST control plane
	DoTListen   string      `yaml:"dot_listen"`   // host:port for DNS-over-TLS (empty = off)
	DoHListen   string      `yaml:"doh_listen"`   // host:port for DNS-over-HTTPS (empty = off)
	TLSCert     string      `yaml:"tls_cert"`     // PEM certificate chain for DoT/DoH
	TLSKey      string      `yaml:"tls_key"`      // PEM private key for DoT/DoH
	LogRetentionDays int    `yaml:"log_retention_days"` // query-log rows older than this are purged
	LogBuffer        int    `yaml:"log_buffer"`         // events buffered before drops begin
	SyslogAddr       string `yaml:"syslog_addr"`        // host:port, UDP syslog sink (empty = off)
	WebhookURL       string `yaml:"webhook_url"`        // POST batches of query-log JSON (empty = off)
	Upstreams   []string    `yaml:"upstreams"`    // plain-DNS upstreams, e.g. 1.1.1.1:53
	SQLitePath  string      `yaml:"sqlite_path"`  // database file
	DataDir     string      `yaml:"data_dir"`     // state dir (blocklists, later)
	Cache       CacheConfig `yaml:"cache"`
}

type CacheConfig struct {
	MaxEntries int    `yaml:"max_entries"`
	MinTTL     uint32 `yaml:"min_ttl"` // seconds, floor applied to cached answers
	MaxTTL     uint32 `yaml:"max_ttl"` // seconds, ceiling applied before caching
}

func Default() Config {
	return Config{
		Listen:     "127.0.0.1:1053",
		APIListen:  "127.0.0.1:8080",
		LogRetentionDays: 7,
		LogBuffer:        4096,
		Upstreams:  []string{"1.1.1.1:53", "8.8.8.8:53"},
		SQLitePath: "data/opencontrol.db",
		DataDir:    "data",
		Cache: CacheConfig{
			MaxEntries: 65536,
			MinTTL:     30,
			MaxTTL:     3600,
		},
	}
}

// Load builds the config: defaults <- YAML file <- environment overrides.
// Env vars: OC_LISTEN, OC_SQLITE_PATH, OC_DATA_DIR.
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
	if v := os.Getenv("OC_LISTEN"); v != "" {
		cfg.Listen = v
	}
	if v := os.Getenv("OC_API_LISTEN"); v != "" {
		cfg.APIListen = v
	}
	if v := os.Getenv("OC_DOT_LISTEN"); v != "" {
		cfg.DoTListen = v
	}
	if v := os.Getenv("OC_DOH_LISTEN"); v != "" {
		cfg.DoHListen = v
	}
	if v := os.Getenv("OC_TLS_CERT"); v != "" {
		cfg.TLSCert = v
	}
	if v := os.Getenv("OC_TLS_KEY"); v != "" {
		cfg.TLSKey = v
	}
	if v := os.Getenv("OC_LOG_RETENTION_DAYS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("OC_LOG_RETENTION_DAYS must be a non-negative integer, got %q", v)
		}
		cfg.LogRetentionDays = n
	}
	if v := os.Getenv("OC_SYSLOG_ADDR"); v != "" {
		cfg.SyslogAddr = v
	}
	if v := os.Getenv("OC_WEBHOOK_URL"); v != "" {
		cfg.WebhookURL = v
	}
	if v := os.Getenv("OC_SQLITE_PATH"); v != "" {
		cfg.SQLitePath = v
	}
	if v := os.Getenv("OC_DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
	return &cfg, nil
}
