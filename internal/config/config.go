// Package config loads and validates GuardBridge's YAML configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Upstream describes the generic OpenAI-compatible chat model that
// GuardBridge calls for audits.
type Upstream struct {
	BaseURL   string `yaml:"base_url"`
	APIKey    string `yaml:"api_key"`
	Model     string `yaml:"model"`
	TimeoutMS int    `yaml:"timeout_ms"`
	MaxTokens int    `yaml:"max_tokens"`
	Seed      *int   `yaml:"seed"` // nil = omit seed
}

// Config is the full GuardBridge configuration.
type Config struct {
	Listen       string   `yaml:"listen"`
	InboundToken string   `yaml:"inbound_token"`
	Upstream     Upstream `yaml:"upstream"`
	SystemPrompt string   `yaml:"system_prompt"`
	LogLevel     string   `yaml:"log_level"`
}

const (
	defaultListen    = "127.0.0.1:8080"
	defaultTimeoutMS = 15000
	defaultMaxTokens = 256
	defaultLogLevel  = "info"
	minTimeoutMS     = 100
	maxTimeoutMS     = 30000
	minMaxTokens     = 64
	maxMaxTokens     = 8192
)

// Load reads and validates a YAML config from path. Defaults are
// applied for empty optional fields: Listen "127.0.0.1:8080",
// TimeoutMS 15000, MaxTokens 256, LogLevel "info". Upstream.BaseURL
// must be an http(s) URL with a host and no user info, query, or
// fragment (mirroring sub2api's NormalizeBaseURL strictness);
// Upstream.Model must be non-empty; TimeoutMS must be in
// [100,30000] and MaxTokens in [64,8192] when set.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	var cfg Config
	// KnownFields makes typos fail startup instead of silently zeroing
	// a key (e.g. "inbound-token" would otherwise disable inbound auth).
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, sanitizeYAMLError(err))
	}
	if err := cfg.applyDefaultsAndValidate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// sanitizeYAMLError redacts the offending scalar that yaml.TypeError
// embeds in its messages, so a secret pasted into a mistyped field
// cannot leak into logs.
func sanitizeYAMLError(err error) error {
	var typeErr *yaml.TypeError
	if errors.As(err, &typeErr) {
		msgs := make([]string, 0, len(typeErr.Errors))
		for _, msg := range typeErr.Errors {
			if i := strings.IndexByte(msg, '`'); i >= 0 {
				if j := strings.LastIndexByte(msg, '`'); j > i {
					msg = msg[:i+1] + "<redacted>" + msg[j:]
				}
			}
			msgs = append(msgs, msg)
		}
		return fmt.Errorf("%s", strings.Join(msgs, "; "))
	}
	return err
}

func (c *Config) applyDefaultsAndValidate() error {
	if strings.TrimSpace(c.Listen) == "" {
		c.Listen = defaultListen
	}
	if strings.TrimSpace(c.LogLevel) == "" {
		c.LogLevel = defaultLogLevel
	}
	if c.Upstream.TimeoutMS == 0 {
		c.Upstream.TimeoutMS = defaultTimeoutMS
	}
	if c.Upstream.MaxTokens == 0 {
		c.Upstream.MaxTokens = defaultMaxTokens
	}
	if _, err := normalizeBaseURL(c.Upstream.BaseURL); err != nil {
		return err
	}
	if strings.TrimSpace(c.Upstream.Model) == "" {
		return fmt.Errorf("config: upstream.model is required")
	}
	if c.Upstream.TimeoutMS < minTimeoutMS || c.Upstream.TimeoutMS > maxTimeoutMS {
		return fmt.Errorf("config: upstream.timeout_ms %d outside [%d,%d]", c.Upstream.TimeoutMS, minTimeoutMS, maxTimeoutMS)
	}
	if c.Upstream.MaxTokens < minMaxTokens || c.Upstream.MaxTokens > maxMaxTokens {
		return fmt.Errorf("config: upstream.max_tokens %d outside [%d,%d]", c.Upstream.MaxTokens, minMaxTokens, maxMaxTokens)
	}
	return nil
}

// normalizeBaseURL validates that raw is an http(s) URL with a host
// and without user info, query, or fragment. It mirrors the strictness
// of sub2api's NormalizeBaseURL so the same classes of endpoint values
// that sub2api rejects are rejected here too.
func normalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("config: upstream.base_url %q is not a valid URL with host", raw)
	}
	if scheme := strings.ToLower(parsed.Scheme); scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("config: upstream.base_url %q must use http or https", raw)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("config: upstream.base_url %q must not contain credentials, query, or fragment", raw)
	}
	if strings.TrimSpace(parsed.Hostname()) == "" {
		return "", fmt.Errorf("config: upstream.base_url %q has no host", raw)
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}
