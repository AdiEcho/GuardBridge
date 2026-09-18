// Package upstream implements GuardBridge's outbound client for
// OpenAI-compatible chat.completions endpoints. It mirrors the transport
// hardening of the sub2api guard scanner it stands in for
// (research/sub2api/backend/internal/securityaudit/prompt_outbound_security.go):
// no ambient proxy, TLS >= 1.2, capped response bodies, and redirects are
// never followed.
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AdiEcho/GuardBridge/internal/config"
	"github.com/AdiEcho/GuardBridge/internal/prompt"
)

// maxUpstreamResponseBytes caps the upstream response body. A guard verdict is
// two lines of text (or a small JSON object); anything larger indicates a
// misbehaving or hostile upstream and is rejected before parsing.
const maxUpstreamResponseBytes int64 = 64 * 1024

// Fallbacks used when the configuration leaves a field unset.
const (
	defaultTimeoutMS = 15000
	defaultMaxTokens = 256
)

// TransportError reports a failure to obtain a usable upstream response: a
// network error, a timeout, a non-2xx HTTP status, an oversized body, or a
// response envelope we cannot extract assistant content from. StatusCode is 0
// when no HTTP status was ever received (network-level failure).
type TransportError struct {
	Timeout    bool
	StatusCode int
	Cause      error
}

// Error never includes the upstream response body (it may echo request or
// account details) nor the API key; only the status code with its standard
// reason phrase, or the transport-level cause.
func (e *TransportError) Error() string {
	if e.StatusCode != 0 {
		if reason := http.StatusText(e.StatusCode); reason != "" {
			return fmt.Sprintf("upstream returned HTTP %d %s", e.StatusCode, reason)
		}
		return fmt.Sprintf("upstream returned HTTP %d", e.StatusCode)
	}
	if e.Timeout {
		if e.Cause != nil {
			return "upstream request timed out: " + e.Cause.Error()
		}
		return "upstream request timed out"
	}
	if e.Cause != nil {
		return "upstream request failed: " + e.Cause.Error()
	}
	return "upstream request failed"
}

// Unwrap exposes the underlying cause (nil for pure status-code failures).
func (e *TransportError) Unwrap() error { return e.Cause }

// Client calls an OpenAI-compatible chat.completions endpoint with the
// hardened transport settings GuardBridge requires.
type Client struct {
	cfg        config.Upstream
	httpClient *http.Client
}

// New builds a Client for the given upstream configuration. Timeout and token
// budget fall back to sane defaults when unset.
func New(cfg config.Upstream) *Client {
	timeoutMS := cfg.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = defaultTimeoutMS
	}
	timeout := time.Duration(timeoutMS) * time.Millisecond
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		// Never inherit HTTP(S)_PROXY: the upstream endpoint is configured
		// explicitly, and an ambient proxy would receive the Authorization
		// header and could reroute traffic to an unintended host.
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	transport.DialContext = dialer.DialContext
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			// Do not follow redirects (http.ErrUseLastResponse): a 3xx from
			// the upstream is surfaced as-is, so a redirect can never
			// silently move the Authorization header to a different origin.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// chatRequest is the outbound payload. temperature is pinned to 0 (verdicts
// must be deterministic) and max_tokens comes from GuardBridge's own config:
// the inbound max_tokens (sub2api sends 64 for the short two-line reply) is
// never forwarded because it would truncate the JSON verdict.
type chatRequest struct {
	Model       string           `json:"model"`
	Messages    []prompt.Message `json:"messages"`
	Temperature float64          `json:"temperature"`
	MaxTokens   int              `json:"max_tokens"`
	Seed        *int             `json:"seed,omitempty"`
}

// ChatCompletions POSTs {base}/v1/chat/completions with the given messages
// and returns the assistant content of choices[0]. The content may be a plain
// string or an array of text parts, mirroring sub2api's extractOpenAIContent
// (prompt_qwen3guard.go:282-318). Every failure is returned as a
// *TransportError.
func (c *Client) ChatCompletions(ctx context.Context, messages []prompt.Message) (string, error) {
	endpoint, err := ChatCompletionsURL(c.cfg.BaseURL)
	if err != nil {
		return "", &TransportError{Cause: err}
	}
	maxTokens := c.cfg.MaxTokens
	if maxTokens <= 0 {
		maxTokens = defaultMaxTokens
	}
	payload := chatRequest{
		Model:       c.cfg.Model,
		Messages:    messages,
		Temperature: 0,
		MaxTokens:   maxTokens,
		Seed:        c.cfg.Seed,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", &TransportError{Cause: fmt.Errorf("encode chat request: %w", err)}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", &TransportError{Cause: err}
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		timeout := errors.Is(err, context.DeadlineExceeded)
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			timeout = true
		}
		return "", &TransportError{Timeout: timeout, Cause: err}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Report only the status code (and its standard reason phrase): the
		// upstream response body may echo request or account details and must
		// never reach logs or callers.
		return "", &TransportError{StatusCode: resp.StatusCode}
	}
	limited := io.LimitReader(resp.Body, maxUpstreamResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return "", &TransportError{Cause: err}
	}
	if int64(len(responseBody)) > maxUpstreamResponseBytes {
		return "", &TransportError{Cause: fmt.Errorf("upstream response exceeds %d bytes", maxUpstreamResponseBytes)}
	}
	content, err := extractContent(responseBody)
	if err != nil {
		return "", &TransportError{Cause: err}
	}
	return content, nil
}

// ChatCompletionsURL normalizes an upstream base URL and appends
// /v1/chat/completions. Mirrors sub2api's ChatCompletionsURL
// (prompt_outbound_security.go:16-48): trailing slashes are stripped, a path
// ending in /v1 is collapsed so no /v1/v1 is produced, and only credential-,
// query-, and fragment-free http(s) URLs are accepted.
func ChatCompletionsURL(base string) (string, error) {
	normalized, err := normalizeBaseURL(base)
	if err != nil {
		return "", err
	}
	return normalized + "/v1/chat/completions", nil
}

func normalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("upstream base URL is invalid")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("upstream base URL scheme must be http or https")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("upstream base URL must not contain user info, query, or fragment")
	}
	if strings.TrimSpace(parsed.Hostname()) == "" {
		return "", errors.New("upstream base URL is invalid")
	}
	path := strings.TrimRight(parsed.EscapedPath(), "/")
	if strings.EqualFold(path, "/v1") {
		path = ""
	}
	parsed.Path = path
	parsed.RawPath = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

// extractContent pulls choices[0].message.content out of an OpenAI
// chat.completions envelope. It mirrors sub2api's extractOpenAIContent
// semantics exactly: string content must be non-blank; array content is the
// non-blank "text" fields of its object parts joined with "\n"; anything else
// (null, numbers, objects) is an error.
func extractContent(body []byte) (string, error) {
	var response struct {
		Choices []struct {
			Message struct {
				Content any `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &response); err != nil || len(response.Choices) == 0 {
		return "", errors.New("upstream response envelope invalid")
	}
	content := response.Choices[0].Message.Content
	switch typed := content.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return "", errors.New("upstream response content empty")
		}
		return typed, nil
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			object, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if text, ok := object["text"].(string); ok && strings.TrimSpace(text) != "" {
				parts = append(parts, text)
			}
		}
		if len(parts) == 0 {
			return "", errors.New("upstream response content empty")
		}
		return strings.Join(parts, "\n"), nil
	default:
		return "", errors.New("upstream response content invalid")
	}
}
