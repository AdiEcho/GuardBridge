package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/AdiEcho/GuardBridge/internal/config"
	"github.com/AdiEcho/GuardBridge/internal/qwen3guard"
	"github.com/AdiEcho/GuardBridge/internal/upstream"
)

const (
	canaryPrompt = "PROMPT_CANARY_SECRET_TEXT"
	canaryKey    = "sk-CANARY-KEY"
)

// capturedUpstream records what the mock guard LLM received.
type capturedUpstream struct {
	mu     sync.Mutex
	bodies []map[string]any
}

func (c *capturedUpstream) record(r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return
	}
	var decoded map[string]any
	_ = json.Unmarshal(body, &decoded)
	c.mu.Lock()
	c.bodies = append(c.bodies, decoded)
	c.mu.Unlock()
}

func (c *capturedUpstream) lastBody(t *testing.T) map[string]any {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.bodies) == 0 {
		t.Fatal("mock upstream captured no requests")
	}
	return c.bodies[len(c.bodies)-1]
}

func (c *capturedUpstream) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

// newTestServer builds a GuardBridge handler in front of a mock upstream
// LLM and returns the httptest server plus the capture log. The log sink
// collects everything the handler logs so tests can assert no secrets leak.
func newTestServer(t *testing.T, cfg config.Config, mock func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, *capturedUpstream, *logSink) {
	t.Helper()
	captured := &capturedUpstream{}
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.record(r)
		mock(w, r)
	}))
	t.Cleanup(upstreamServer.Close)

	cfg.Upstream = config.Upstream{
		BaseURL:   upstreamServer.URL,
		APIKey:    canaryKey,
		Model:     orDefault(cfg.Upstream.Model, "guard-llm-test"),
		TimeoutMS: orDefaultInt(cfg.Upstream.TimeoutMS, 5000),
		MaxTokens: orDefaultInt(cfg.Upstream.MaxTokens, 256),
	}
	sink := &logSink{}
	handler := New(cfg, upstream.New(cfg.Upstream))
	handler.SetLogger(sink.logger())
	server := httptest.NewServer(handler.Routes())
	t.Cleanup(server.Close)
	return server, captured, sink
}

// logSink captures structured log output for leak assertions.
type logSink struct {
	buf bytes.Buffer
}

func (s *logSink) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&s.buf, nil))
}

func (s *logSink) output() string { return s.buf.String() }

// postChat sends a chat.completions request to the GuardBridge server.
func postChat(t *testing.T, server *httptest.Server, headers map[string]string, body string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()
	return resp, string(raw)
}

// decodeContent extracts choices[0].message.content from a response body.
func decodeContent(t *testing.T, body string) string {
	t.Helper()
	var envelope struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("decode response envelope %q: %v", body, err)
	}
	if len(envelope.Choices) == 0 {
		t.Fatalf("response has no choices: %q", body)
	}
	return envelope.Choices[0].Message.Content
}

func decodeErrorCode(t *testing.T, body string) string {
	t.Helper()
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("decode error envelope %q: %v", body, err)
	}
	return envelope.Error.Code
}

func baseCfg() config.Config {
	return config.Config{LogLevel: "info"}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func orDefaultInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// --- Scan-shaped probe and happy paths ---

// TestScanShapedProbeJSONPath is the spec acceptance probe: sub2api's exact
// Scan payload shape, a mock upstream returning the JSON verdict, and the
// contract parse succeeding on the reply GuardBridge produces.
func TestScanShapedProbeJSONPath(t *testing.T) {
	server, _, _ := newTestServer(t, baseCfg(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"safety\":\"Unsafe\",\"categories\":[\"Jailbreak\"]}"}}]}`))
	})
	body := `{"model":"gpt-x","messages":[{"role":"user","content":"` + canaryPrompt + `"}],"temperature":0,"max_tokens":64,"seed":42}`
	resp, raw := postChat(t, server, nil, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	content := decodeContent(t, raw)
	if content != "Safety: Unsafe\nCategories: Jailbreak" {
		t.Fatalf("content = %q, want two-line verdict", content)
	}
	if _, err := qwen3guard.ParseLines(content); err != nil {
		t.Fatalf("contract ParseLines rejected GuardBridge output %q: %v", content, err)
	}
	if !strings.HasPrefix(content, "Safety: Unsafe") {
		t.Fatalf("content %q must start with the Safety line", content)
	}
}

func TestPlaintextFallbackEndToEnd(t *testing.T) {
	server, _, sink := newTestServer(t, baseCfg(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"Safety: Safe\nCategories: None"}}]}`))
	})
	resp, raw := postChat(t, server, nil, `{"model":"gpt-x","messages":[{"role":"user","content":"hi"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	content := decodeContent(t, raw)
	if content != "Safety: Safe\nCategories: None" {
		t.Fatalf("content = %q, want exact two-line plaintext", content)
	}
	if _, err := qwen3guard.ParseLines(content); err != nil {
		t.Fatalf("contract ParseLines rejected output %q: %v", content, err)
	}
	if !strings.Contains(sink.output(), "parse_path=plaintext") {
		t.Fatalf("log output %q must record parse_path=plaintext", sink.output())
	}
}

func TestJSONWithFenceWrapper(t *testing.T) {
	// The upstream model wraps its JSON verdict in a markdown fence.
	fenced := "```json\n{\"safety\":\"Safe\",\"categories\":[\"None\"],\"extra\":\"ignored\"}\n```"
	server, _, _ := newTestServer(t, baseCfg(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"content": fenced}}},
		})
	})
	resp, raw := postChat(t, server, nil, `{"model":"gpt-x","messages":[{"role":"user","content":"hi"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	content := decodeContent(t, raw)
	if content != "Safety: Safe\nCategories: None" {
		t.Fatalf("content = %q, want two-line render of fenced JSON verdict", content)
	}
	if _, err := qwen3guard.ParseLines(content); err != nil {
		t.Fatalf("contract ParseLines rejected output %q: %v", content, err)
	}
}

// --- outbound message shaping ---

func TestOnlyLastUserTextIsAudited(t *testing.T) {
	server, captured, _ := newTestServer(t, baseCfg(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"safety\":\"Safe\",\"categories\":[\"None\"]}"}}]}`))
	})
	body := `{"model":"gpt-x","messages":[{"role":"system","content":"be nice"},{"role":"user","content":"first"},{"role":"assistant","content":"reply"},{"role":"user","content":"real chunk"}]}`
	resp, raw := postChat(t, server, nil, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	outbound := captured.lastBody(t)
	messages, ok := outbound["messages"].([]any)
	if !ok || len(messages) != 2 {
		t.Fatalf("outbound messages = %#v, want exactly [system, user]", outbound["messages"])
	}
	first, _ := messages[0].(map[string]any)
	if first["role"] != "system" {
		t.Fatalf("first outbound message role = %v, want system", first["role"])
	}
	if first["content"] == "be nice" {
		t.Fatal("inbound system content must never become the outbound system prompt")
	}
	if strings.TrimSpace(first["content"].(string)) == "" {
		t.Fatal("outbound system prompt is empty")
	}
	last, _ := messages[1].(map[string]any)
	if last["role"] != "user" || last["content"] != "real chunk" {
		t.Fatalf("last outbound message = %v/%v, want user \"real chunk\"", last["role"], last["content"])
	}
	// Inbound garbage generation params are never forwarded.
	if _, present := outbound["stream"]; present {
		t.Fatal("outbound request must not contain stream")
	}
	if outbound["temperature"] != float64(0) {
		t.Fatalf("outbound temperature = %v, want 0 (pinned, not inbound)", outbound["temperature"])
	}
	if outbound["max_tokens"] != float64(256) {
		t.Fatalf("outbound max_tokens = %v, want configured 256", outbound["max_tokens"])
	}
}

func TestCustomSystemPromptAppearsOutbound(t *testing.T) {
	cfg := baseCfg()
	cfg.SystemPrompt = "CUSTOM_PROMPT_MARKER: audit strictly."
	server, captured, _ := newTestServer(t, cfg, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"safety\":\"Safe\",\"categories\":[]}"}}]}`))
	})
	resp, raw := postChat(t, server, nil, `{"model":"gpt-x","messages":[{"role":"user","content":"hi"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	outbound := captured.lastBody(t)
	messages := outbound["messages"].([]any)
	first, _ := messages[0].(map[string]any)
	if first["content"] != "CUSTOM_PROMPT_MARKER: audit strictly." {
		t.Fatalf("configured system prompt = %v, want the custom marker", first["content"])
	}
}

// --- fail-closed inbound validation ---

func TestNoUserMessageRejected(t *testing.T) {
	server, captured, _ := newTestServer(t, baseCfg(), func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream must not be called when there is no user content")
	})
	resp, raw := postChat(t, server, nil, `{"model":"gpt-x","messages":[{"role":"system","content":"s"},{"role":"assistant","content":"a"}]}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", resp.StatusCode, raw)
	}
	if code := decodeErrorCode(t, raw); code != "no_user_content" {
		t.Fatalf("error code = %q, want no_user_content", code)
	}
	if captured.count() != 0 {
		t.Fatalf("upstream called %d times, want 0", captured.count())
	}
}

func TestEmptyUserContentRejected(t *testing.T) {
	server, captured, _ := newTestServer(t, baseCfg(), func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream must not be called for empty user content")
	})
	for _, body := range []string{
		`{"model":"gpt-x","messages":[{"role":"user","content":""}]}`,
		`{"model":"gpt-x","messages":[{"role":"user","content":"   "}]}`,
		`{"model":"gpt-x","messages":[{"role":"user","content":null}]}`,
	} {
		resp, raw := postChat(t, server, nil, body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("body %s: status = %d, want 400", body, resp.StatusCode)
		}
		if code := decodeErrorCode(t, raw); code != "no_user_content" {
			t.Fatalf("body %s: error code = %q, want no_user_content", body, code)
		}
	}
	if captured.count() != 0 {
		t.Fatalf("upstream called %d times, want 0", captured.count())
	}
}

func TestTextBlockArrayContentAudited(t *testing.T) {
	server, captured, _ := newTestServer(t, baseCfg(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"safety\":\"Safe\",\"categories\":[\"None\"]}"}}]}`))
	})
	body := `{"model":"gpt-x","messages":[{"role":"user","content":[{"type":"text","text":"part one"},{"type":"text","text":"part two"}]}]}`
	resp, raw := postChat(t, server, nil, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	outbound := captured.lastBody(t)
	messages := outbound["messages"].([]any)
	last, _ := messages[len(messages)-1].(map[string]any)
	if last["content"] != "part one\npart two" {
		t.Fatalf("audited chunk = %v, want text parts joined with newline", last["content"])
	}
}

func TestStreamRejected(t *testing.T) {
	server, captured, _ := newTestServer(t, baseCfg(), func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream must not be called for streaming requests")
	})
	resp, raw := postChat(t, server, nil, `{"model":"gpt-x","messages":[{"role":"user","content":"hi"}],"stream":true}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", resp.StatusCode, raw)
	}
	if code := decodeErrorCode(t, raw); code != "stream_not_supported" {
		t.Fatalf("error code = %q, want stream_not_supported", code)
	}
	if captured.count() != 0 {
		t.Fatalf("upstream called %d times, want 0", captured.count())
	}
}

func TestGarbageBodyRejected(t *testing.T) {
	server, _, _ := newTestServer(t, baseCfg(), func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream must not be called for a garbage body")
	})
	resp, raw := postChat(t, server, nil, `this is not json`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", resp.StatusCode, raw)
	}
}

// --- upstream failures map to fail-closed 5xx ---

func TestUpstream500Becomes502(t *testing.T) {
	server, _, sink := newTestServer(t, baseCfg(), func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream exploded "+canaryKey, http.StatusInternalServerError)
	})
	resp, raw := postChat(t, server, nil, `{"model":"gpt-x","messages":[{"role":"user","content":"`+canaryPrompt+`"}]}`)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (body %s)", resp.StatusCode, raw)
	}
	if code := decodeErrorCode(t, raw); code != "upstream_unavailable" {
		t.Fatalf("error code = %q, want upstream_unavailable", code)
	}
	if strings.Contains(raw, "Safety:") {
		t.Fatalf("error body %q must not contain a Safety line", raw)
	}
	if strings.Contains(raw, canaryKey) || strings.Contains(sink.output(), canaryKey) {
		t.Fatal("API key leaked into response or logs")
	}
	if strings.Contains(sink.output(), canaryPrompt) {
		t.Fatal("user prompt leaked into logs")
	}
}

func TestUpstreamTimeoutBecomes504(t *testing.T) {
	release := make(chan struct{})
	cfg := baseCfg()
	cfg.Upstream.TimeoutMS = 50
	server, _, _ := newTestServer(t, cfg, func(w http.ResponseWriter, r *http.Request) {
		<-release // block well past the 50ms upstream timeout
	})
	defer close(release)
	resp, raw := postChat(t, server, nil, `{"model":"gpt-x","messages":[{"role":"user","content":"hi"}]}`)
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504 (body %s)", resp.StatusCode, raw)
	}
	if code := decodeErrorCode(t, raw); code != "upstream_unavailable" {
		t.Fatalf("error code = %q, want upstream_unavailable", code)
	}
	if strings.Contains(raw, "Safety:") {
		t.Fatalf("error body %q must not contain a Safety line", raw)
	}
}

func TestUpstreamGarbageVerdictBecomes502InvalidGuardOutput(t *testing.T) {
	server, _, sink := newTestServer(t, baseCfg(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"I think this is fine"}}]}`))
	})
	resp, raw := postChat(t, server, nil, `{"model":"gpt-x","messages":[{"role":"user","content":"`+canaryPrompt+`"}]}`)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (body %s)", resp.StatusCode, raw)
	}
	if code := decodeErrorCode(t, raw); code != "invalid_guard_output" {
		t.Fatalf("error code = %q, want invalid_guard_output", code)
	}
	if strings.Contains(raw, "Safety:") || strings.Contains(raw, "I think this is fine") {
		t.Fatalf("error body %q must not contain a Safety line or upstream content", raw)
	}
	if strings.Contains(sink.output(), "I think this is fine") {
		t.Fatal("raw upstream content leaked into logs")
	}
}

// --- inbound auth ---

func TestInboundTokenEnforced(t *testing.T) {
	cfg := baseCfg()
	cfg.InboundToken = "secret-inbound-token"
	server, _, _ := newTestServer(t, cfg, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"safety\":\"Safe\",\"categories\":[\"None\"]}"}}]}`))
	})
	body := `{"model":"gpt-x","messages":[{"role":"user","content":"hi"}]}`

	for name, headers := range map[string]map[string]string{
		"missing auth":  nil,
		"wrong scheme":  {"Authorization": "Basic secret-inbound-token"},
		"wrong token":   {"Authorization": "Bearer nope"},
		"token in body": {"X-Internal": "secret-inbound-token"},
	} {
		resp, raw := postChat(t, server, headers, body)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401 (body %s)", name, resp.StatusCode, raw)
		}
	}

	resp, raw := postChat(t, server, map[string]string{"Authorization": "Bearer secret-inbound-token"}, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("correct token: status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
}

// --- routing ---

func TestUnknownPathAndWrongMethod404(t *testing.T) {
	server, _, _ := newTestServer(t, baseCfg(), func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream must not be called for unrouted requests")
	})
	for _, tc := range []struct {
		name   string
		method string
		path   string
	}{
		{"unknown path", http.MethodPost, "/v1/models"},
		{"root", http.MethodPost, "/"},
		{"wrong method on valid path", http.MethodGet, "/v1/chat/completions"},
		{"delete on valid path", http.MethodDelete, "/v1/chat/completions"},
	} {
		req, err := http.NewRequest(tc.method, server.URL+tc.path, nil)
		if err != nil {
			t.Fatalf("%s: build request: %v", tc.name, err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: do request: %v", tc.name, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404 (body %s)", tc.name, resp.StatusCode, raw)
		}
	}
}

// --- response envelope shape ---

func TestResponseModelEchoesInboundModel(t *testing.T) {
	server, _, _ := newTestServer(t, baseCfg(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"safety\":\"Safe\",\"categories\":[\"None\"]}"}}]}`))
	})
	resp, raw := postChat(t, server, nil, `{"model":"sub2api-node-model","messages":[{"role":"user","content":"hi"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var envelope struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Created int64  `json:"created"`
		Model   string `json:"model"`
	}
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if envelope.Model != "sub2api-node-model" {
		t.Fatalf("model = %q, want inbound model echoed", envelope.Model)
	}
	if !strings.HasPrefix(envelope.ID, "chatcmpl-") {
		t.Fatalf("id = %q, want chatcmpl- prefix", envelope.ID)
	}
	if envelope.Object != "chat.completion" {
		t.Fatalf("object = %q, want chat.completion", envelope.Object)
	}
	if envelope.Created <= 0 {
		t.Fatalf("created = %d, want unix timestamp", envelope.Created)
	}
}

func TestResponseModelDefaultsWhenInboundModelAbsent(t *testing.T) {
	server, _, _ := newTestServer(t, baseCfg(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"safety\":\"Safe\",\"categories\":[\"None\"]}"}}]}`))
	})
	resp, raw := postChat(t, server, nil, `{"messages":[{"role":"user","content":"hi"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var envelope struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if envelope.Model != "guardbridge" {
		t.Fatalf("model = %q, want guardbridge default", envelope.Model)
	}
}

// --- canary leak audit (spec AC) ---

func TestNoCanaryLeakAcrossPaths(t *testing.T) {
	// Success path.
	server, _, sink := newTestServer(t, baseCfg(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"safety\":\"Safe\",\"categories\":[\"None\"]}"}}]}`))
	})
	_, raw := postChat(t, server, nil, `{"model":"gpt-x","messages":[{"role":"user","content":"`+canaryPrompt+`"}]}`)
	assertNoCanary(t, "success path response", raw)
	assertNoCanary(t, "success path logs", sink.output())

	// Failure path (upstream 500 with canaries in body).
	server2, _, sink2 := newTestServer(t, baseCfg(), func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error "+canaryKey+" for "+canaryPrompt, http.StatusInternalServerError)
	})
	resp, raw2 := postChat(t, server2, nil, `{"model":"gpt-x","messages":[{"role":"user","content":"`+canaryPrompt+`"}]}`)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	assertNoCanary(t, "failure path response", raw2)
	assertNoCanary(t, "failure path logs", sink2.output())

	// Parse-failure path with canary embedded in unparseable output.
	server3, _, sink3 := newTestServer(t, baseCfg(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"cannot decide about ` + canaryPrompt + ` really"}}]}`))
	})
	resp3, raw3 := postChat(t, server3, nil, `{"model":"gpt-x","messages":[{"role":"user","content":"`+canaryPrompt+`"}]}`)
	if resp3.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp3.StatusCode)
	}
	assertNoCanary(t, "parse-failure path response", raw3)
	assertNoCanary(t, "parse-failure path logs", sink3.output())

	// Unauthorized path with canary as the wrong token (never logged).
	cfg := baseCfg()
	cfg.InboundToken = "correct-token"
	server4, _, sink4 := newTestServer(t, cfg, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"safety\":\"Safe\",\"categories\":[\"None\"]}"}}]}`))
	})
	resp4, raw4 := postChat(t, server4, map[string]string{"Authorization": "Bearer " + canaryPrompt}, `{"model":"gpt-x","messages":[{"role":"user","content":"hi"}]}`)
	if resp4.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp4.StatusCode)
	}
	assertNoCanary(t, "unauthorized path response", raw4)
	assertNoCanary(t, "unauthorized path logs", sink4.output())
}

func assertNoCanary(t *testing.T, label, haystack string) {
	t.Helper()
	for _, needle := range []string{canaryPrompt, canaryKey} {
		if strings.Contains(haystack, needle) {
			t.Fatalf("%s leaks canary %q", label, needle)
		}
	}
}
