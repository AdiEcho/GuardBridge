// Command guardbridge runs the GuardBridge proxy: an OpenAI-compatible
// inbound endpoint that answers every chat completion with a Qwen3Guard
// two-line safety verdict produced by a generic upstream chat LLM.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/AdiEcho/GuardBridge/internal/config"
	"github.com/AdiEcho/GuardBridge/internal/server"
	"github.com/AdiEcho/GuardBridge/internal/upstream"
)

func main() {
	configPath := flag.String("config", "config.example.yaml", "path to the YAML configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "guardbridge: failed to load config %q: %v\n", *configPath, err)
		os.Exit(1)
	}

	logger := newLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	up := upstream.New(cfg.Upstream)
	handler := server.New(cfg, up)

	promptSource := "default"
	if strings.TrimSpace(cfg.SystemPrompt) != "" {
		promptSource = "configured"
	}
	if cfg.InboundToken == "" && !isLoopbackListen(cfg.Listen) {
		logger.Warn("listening on a non-loopback address without inbound_token; " +
			"anyone who can reach this address can spend your upstream API key")
	}
	// Never log the base URL with credentials or the API key; the bare
	// scheme+host is enough to confirm which endpoint was configured.
	logger.Info("guardbridge starting",
		"listen", cfg.Listen,
		"upstream_model", cfg.Upstream.Model,
		"upstream_host", upstreamHost(cfg.Upstream.BaseURL),
		"prompt", promptSource,
	)

	if err := server.ListenAndServe(cfg, handler); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("guardbridge stopped", "error", err)
		os.Exit(1)
	}
}

// newLogger maps the configured level onto slog. Unknown levels default to
// info rather than failing startup.
func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

// isLoopbackListen reports whether the listen address binds loopback
// only (127.x.x.x, ::1, or localhost).
func isLoopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "localhost" || host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// upstreamHost returns scheme://host of the configured base URL for the
// startup log, or "<invalid>" when it cannot be parsed. It strips any path,
// query, fragment, or user info so credentials never reach the log line.
func upstreamHost(baseURL string) string {
	const invalid = "<invalid>"
	raw := strings.TrimSpace(baseURL)
	if raw == "" {
		return invalid
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return invalid
	}
	scheme = strings.ToLower(scheme)
	if scheme != "http" && scheme != "https" {
		return invalid
	}
	rest, _, _ = strings.Cut(rest, "/")
	rest, _, _ = strings.Cut(rest, "?")
	rest, _, _ = strings.Cut(rest, "#")
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:] // drop user info
	}
	if rest == "" {
		return invalid
	}
	return scheme + "://" + rest
}
