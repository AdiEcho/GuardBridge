package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/AdiEcho/GuardBridge/internal/config"
	"github.com/AdiEcho/GuardBridge/internal/prompt"
)

func TestChatCompletionsURL(t *testing.T) {
	tests := []struct {
		name string
		base string
		want string
	}{
		{"bare host", "http://h", "http://h/v1/chat/completions"},
		{"trailing slash", "http://h/", "http://h/v1/chat/completions"},
		{"v1 suffix", "http://h/v1", "http://h/v1/chat/completions"},
		{"v1 suffix trailing slash", "http://h/v1/", "http://h/v1/chat/completions"},
		{"openai style", "https://api.openai.com/v1", "https://api.openai.com/v1/chat/completions"},
		{"uppercase V1 collapsed", "http://h/V1", "http://h/v1/chat/completions"},
		{"spaces trimmed", "  http://h  ", "http://h/v1/chat/completions"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ChatCompletionsURL(tt.base)
			if err != nil {
				t.Fatalf("ChatCompletionsURL(%q) error: %v", tt.base, err)
			}
			if got != tt.want {
				t.Fatalf("ChatCompletionsURL(%q) = %q, want %q", tt.base, got, tt.want)
			}
		})
	}
}

func TestChatCompletionsURLInvalid(t *testing.T) {
	for _, base := range []string{
		"ftp://h",
		"http://h?x=1",
		"http://u:p@h",
		"",
		"http://h#frag",
		"://missing-scheme",
		"http://",
	} {
		if _, err := ChatCompletionsURL(base); err == nil {
			t.Fatalf("ChatCompletionsURL(%q) unexpectedly succeeded", base)
		}
	}
}

// capturedRequest records what the mock upstream received.
type capturedRequest struct {
	Method string
	Path   string
	Header http.Header
	Body   map[string]any
}

// mockUpstream spins up an httptest server and records every inbound request.
type mockUpstream struct {
	t       *testing.T
	handler func(w http.ResponseWriter, r *http.Request)
	server  *httptest.Server

	mu       sync.Mutex
	captured []capturedRequest
}

func newMockUpstream(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *mockUpstream {
	t.Helper()
	m := &mockUpstream{t: t, handler: handler}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "mock read failure", http.StatusInternalServerError)
			return
		}
		var decoded map[string]any
		_ = json.Unmarshal(body, &decoded)
		m.mu.Lock()
		m.captured = append(m.captured, capturedRequest{
			Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: decoded,
		})
		m.mu.Unlock()
		m.handler(w, r)
	}))
	m.server = server
	t.Cleanup(server.Close)
	return m
}

// URL returns the mock server's base URL.
func (m *mockUpstream) URL() string { return m.server.URL }

// last returns the most recent captured request.
func (m *mockUpstream) last() capturedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.captured) == 0 {
		m.t.Fatal("mock upstream captured no requests")
	}
	return m.captured[len(m.captured)-1]
}

// requests returns a copy of the captured request log.
func (m *mockUpstream) requests() []capturedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]capturedRequest, len(m.captured))
	copy(out, m.captured)
	return out
}

func TestChatCompletionsHappyPathStringContent(t *testing.T) {
	m := newMockUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"Safety: Safe\nCategories: None"}}]}`))
	})
	seed := 42
	cfg := testConfig(m.URL(), "sk-test-key")
	cfg.Seed = &seed
	client := New(cfg)
	got, err := client.ChatCompletions(context.Background(), []prompt.Message{promptMessage("audited chunk")})
	if err != nil {
		t.Fatalf("ChatCompletions error: %v", err)
	}
	if got != "Safety: Safe\nCategories: None" {
		t.Fatalf("content = %q, want the two-line verdict", got)
	}
	cap := m.last()
	if cap.Method != http.MethodPost {
		t.Fatalf("method = %s, want POST", cap.Method)
	}
	if cap.Path != "/v1/chat/completions" {
		t.Fatalf("path = %s, want /v1/chat/completions", cap.Path)
	}
	if got, want := cap.Body["temperature"], float64(0); got != want {
		t.Fatalf("temperature = %v, want %v", got, want)
	}
	if got, want := cap.Body["max_tokens"], float64(256); got != want {
		t.Fatalf("max_tokens = %v, want %v", got, want)
	}
	if got, want := cap.Body["seed"], float64(42); got != want {
		t.Fatalf("seed = %v, want %v (present when configured)", got, want)
	}
	if got, want := cap.Body["model"], "test-model"; got != want {
		t.Fatalf("model = %v, want %v", got, want)
	}
	if auth := cap.Header.Get("Authorization"); auth != "Bearer sk-test-key" {
		t.Fatalf("Authorization = %q, want Bearer sk-test-key", auth)
	}
	messages, ok := cap.Body["messages"].([]any)
	if !ok || len(messages) != 1 {
		t.Fatalf("messages = %#v, want a single message", cap.Body["messages"])
	}
}

func TestChatCompletionsSeedOmittedWhenNilAndNoKeyMeansNoAuthHeader(t *testing.T) {
	m := newMockUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"Safety: Safe\nCategories: None"}}]}`))
	})
	client := New(testConfig(m.URL(), ""))
	if _, err := client.ChatCompletions(context.Background(), []prompt.Message{promptMessage("x")}); err != nil {
		t.Fatalf("ChatCompletions error: %v", err)
	}
	cap := m.last()
	if _, present := cap.Body["seed"]; present {
		t.Fatalf("seed = %v, want absent when nil", cap.Body["seed"])
	}
	if auth := cap.Header.Get("Authorization"); auth != "" {
		t.Fatalf("Authorization = %q, want empty when no API key configured", auth)
	}
}

func TestChatCompletionsTextBlockArrayContent(t *testing.T) {
	m := newMockUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":[{"type":"text","text":"Safety: Safe"},{"type":"text","text":"Categories: None"}]}}]}`))
	})
	client := New(testConfig(m.URL(), ""))
	got, err := client.ChatCompletions(context.Background(), []prompt.Message{promptMessage("x")})
	if err != nil {
		t.Fatalf("ChatCompletions error: %v", err)
	}
	if got != "Safety: Safe\nCategories: None" {
		t.Fatalf("content = %q, want text parts joined with newline", got)
	}
}

func TestChatCompletionsHTTPStatusErrors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"internal server error", 500},
		{"unauthorized", 401},
		{"too many requests", 429},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMockUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			})
			client := New(testConfig(m.URL(), "sk-test-key"))
			content, err := client.ChatCompletions(context.Background(), []prompt.Message{promptMessage("x")})
			if err == nil {
				t.Fatalf("expected error for status %d, got content %q", tt.statusCode, content)
			}
			var te *TransportError
			if !errors.As(err, &te) {
				t.Fatalf("error = %T, want *TransportError: %v", err, err)
			}
			if te.StatusCode != tt.statusCode {
				t.Fatalf("TransportError.StatusCode = %d, want %d", te.StatusCode, tt.statusCode)
			}
		})
	}
}

func TestChatCompletionsRedirectNotFollowed(t *testing.T) {
	m := newMockUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://evil.example/steal")
		w.WriteHeader(http.StatusMovedPermanently)
	})
	client := New(testConfig(m.URL(), "sk-test-key"))
	content, err := client.ChatCompletions(context.Background(), []prompt.Message{promptMessage("x")})
	if err == nil {
		t.Fatalf("expected error for 301, got content %q", content)
	}
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("error = %T, want *TransportError: %v", err, err)
	}
	if te.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("TransportError.StatusCode = %d, want 301", te.StatusCode)
	}
	// ErrUseLastResponse: exactly one request was made — the redirect to
	// evil.example was never followed.
	if got := len(m.requests()); got != 1 {
		t.Fatalf("%d requests captured, want 1 (redirect must not be followed)", got)
	}
}

func TestChatCompletionsTimeout(t *testing.T) {
	release := make(chan struct{})
	m := newMockUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		<-release // block well past the client timeout
	})
	defer close(release)
	cfg := testConfig(m.URL(), "")
	cfg.TimeoutMS = 50
	client := New(cfg)
	content, err := client.ChatCompletions(context.Background(), []prompt.Message{promptMessage("x")})
	if err == nil {
		t.Fatalf("expected timeout error, got content %q", content)
	}
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("error = %T, want *TransportError: %v", err, err)
	}
	if !te.Timeout {
		t.Fatalf("TransportError.Timeout = false, want true (%v)", err)
	}
	if te.StatusCode != 0 {
		t.Fatalf("TransportError.StatusCode = %d, want 0 for network-level failure", te.StatusCode)
	}
}

func TestChatCompletionsOversizedBody(t *testing.T) {
	m := newMockUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(oversizedBody(64*1024 + 1))
	})
	client := New(testConfig(m.URL(), ""))
	_, err := client.ChatCompletions(context.Background(), []prompt.Message{promptMessage("x")})
	if err == nil {
		t.Fatal("expected error for oversized body, got nil")
	}
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("error = %T, want *TransportError: %v", err, err)
	}
}

func TestChatCompletionsBadContentShapes(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"empty choices", `{"choices":[]}`},
		{"null content", `{"choices":[{"message":{"content":null}}]}`},
		{"empty string content", `{"choices":[{"message":{"content":""}}]}`},
		{"whitespace content", `{"choices":[{"message":{"content":"   \n\t  "}}]}`},
		{"numeric content", `{"choices":[{"message":{"content":7}}]}`},
		{"garbage envelope", `not json at all`},
		{"empty text blocks", `{"choices":[{"message":{"content":[{"type":"text","text":"  "},{"type":"other"}]}}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMockUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.body))
			})
			client := New(testConfig(m.URL(), ""))
			content, err := client.ChatCompletions(context.Background(), []prompt.Message{promptMessage("x")})
			if err == nil {
				t.Fatalf("expected error, got content %q", content)
			}
			var te *TransportError
			if !errors.As(err, &te) {
				t.Fatalf("error = %T, want *TransportError: %v", err, err)
			}
			if strings.Contains(te.Error(), "Safety") {
				t.Fatalf("error message leaks verdict-shaped content: %v", te)
			}
		})
	}
}

func TestChatCompletionsInvalidBaseURL(t *testing.T) {
	for _, base := range []string{"", "ftp://h", "http://u:p@h"} {
		client := New(testConfig(base, ""))
		if _, err := client.ChatCompletions(context.Background(), []prompt.Message{promptMessage("x")}); err == nil {
			t.Fatalf("expected error for base URL %q", base)
		}
	}
}

func TestTransportErrorMessage(t *testing.T) {
	te := &TransportError{StatusCode: 500}
	if got := te.Error(); !strings.Contains(got, "500") {
		t.Fatalf("Error() = %q, want status code present", got)
	}
	if te.Unwrap() != nil {
		t.Fatalf("Unwrap() = %v, want nil for status-only errors", te.Unwrap())
	}
	withCause := &TransportError{Timeout: true, Cause: errors.New("boom")}
	if withCause.Unwrap() == nil {
		t.Fatal("Unwrap() = nil, want the cause")
	}
}

// --- test helpers ---

func testConfig(baseURL, apiKey string) config.Upstream {
	return config.Upstream{
		BaseURL:   baseURL,
		APIKey:    apiKey,
		Model:     "test-model",
		TimeoutMS: 5000,
		MaxTokens: 256,
	}
}

// promptMessage builds a user message for outbound calls.
func promptMessage(content string) prompt.Message {
	return prompt.Message{Role: "user", Content: content}
}

// oversizedBody returns a JSON string body of exactly n bytes.
func oversizedBody(n int) []byte {
	prefix := []byte(`{"choices":[{"message":{"content":"`)
	suffix := []byte(`"}}]}`)
	pad := n - len(prefix) - len(suffix)
	body := make([]byte, 0, n)
	body = append(body, prefix...)
	for i := 0; i < pad; i++ {
		body = append(body, 'a')
	}
	body = append(body, suffix...)
	return body
}
