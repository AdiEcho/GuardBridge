// Package server implements GuardBridge's inbound HTTP API: a single POST
// /v1/chat/completions route that sub2api calls exactly as it would call any
// OpenAI-compatible Guard node.
package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AdiEcho/GuardBridge/internal/config"
	"github.com/AdiEcho/GuardBridge/internal/parse"
	"github.com/AdiEcho/GuardBridge/internal/prompt"
	"github.com/AdiEcho/GuardBridge/internal/qwen3guard"
	"github.com/AdiEcho/GuardBridge/internal/upstream"
)

// maxInboundBodyBytes caps the inbound request body. A guard probe carries
// one user chunk; anything larger is rejected before decoding.
const maxInboundBodyBytes int64 = 1 << 20 // 1 MiB

// Handler serves the GuardBridge inbound API.
type Handler struct {
	cfg          config.Config
	upstream     *upstream.Client
	systemPrompt string
	logger       *slog.Logger
	requestSeq   atomic.Uint64
}

// New builds a Handler from the loaded configuration and upstream client.
func New(cfg config.Config, up *upstream.Client) *Handler {
	return &Handler{
		cfg:          cfg,
		upstream:     up,
		systemPrompt: prompt.Select(cfg.SystemPrompt),
		logger:       slog.Default(),
	}
}

// SetLogger overrides the handler logger (used by tests to capture output).
func (h *Handler) SetLogger(l *slog.Logger) { h.logger = l }

// Routes returns the mux serving POST /v1/chat/completions. Every other
// path — and every other method on the one route — is a 404. We choose 404
// over 405 deliberately: sub2api only ever POSTs this one route, so a 405
// distinction adds nothing and a uniform 404 keeps the error surface tiny.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", h.handleChatCompletions)
	return mux
}

func (h *Handler) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusNotFound, "not_found", "unknown route")
		return
	}
	requestID := h.nextRequestID()

	// The inbound Authorization header is never logged, present or not.
	if !h.authorize(r) {
		h.logger.Warn("request rejected",
			"request_id", requestID, "status", http.StatusUnauthorized, "reason", "unauthorized")
		h.writeUnauthorized(w)
		return
	}

	var req inboundRequest
	body := http.MaxBytesReader(w, r.Body, maxInboundBodyBytes)
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(&req); err != nil {
		h.logger.Warn("request rejected",
			"request_id", requestID, "status", http.StatusBadRequest, "reason", "invalid request body")
		h.writeError(w, http.StatusBadRequest, "invalid_request", "request body is not a valid OpenAI chat request")
		return
	}
	// Reject trailing data so a body containing multiple JSON values or
	// non-whitespace garbage cannot be partially accepted.
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		h.logger.Warn("request rejected",
			"request_id", requestID, "status", http.StatusBadRequest, "reason", "trailing request body")
		h.writeError(w, http.StatusBadRequest, "invalid_request", "request body is not a valid OpenAI chat request")
		return
	}
	if req.Stream {
		// v1 decision: never half-implement SSE. A streaming client gets an
		// explicit 400 instead of a silently degraded non-stream reply.
		h.logger.Warn("request rejected",
			"request_id", requestID, "status", http.StatusBadRequest, "reason", "stream not supported")
		h.writeError(w, http.StatusBadRequest, "stream_not_supported", "streaming is not supported")
		return
	}

	userChunk, ok := extractLastUserText(req.Messages)
	if !ok {
		h.logger.Warn("request rejected",
			"request_id", requestID, "status", http.StatusBadRequest, "reason", "no user content")
		h.writeError(w, http.StatusBadRequest, "no_user_content", "no user message with non-empty text content")
		return
	}

	messages := prompt.OutboundMessages(h.systemPrompt, userChunk)
	content, err := h.upstream.ChatCompletions(r.Context(), messages)
	if err != nil {
		h.handleUpstreamError(w, requestID, err)
		return
	}

	// Parse failure is fail-closed: GuardBridge never forges a Safety line.
	// We answer 502 (not 200-with-garbage) so sub2api's HTTPStatus path
	// treats the node as unavailable rather than running ParseQwen3Guard
	// over a fake verdict. Retry semantics: within sub2api, HTTP 5xx maps
	// to ErrorCodeUnavailable and is retried later; a 200 with an
	// unparseable body would be terminal ErrorCodeInvalidResponse with no
	// retry (prompt_qwen3guard.go:234-236 maps only 429/>=500 to retryable).
	// Retryable-unavailable is the deliberate tradeoff: a chatty model or
	// transient glitch is retried, never silently trusted (Critic minor #1).
	res, err := parse.Parse(content)
	if err != nil {
		h.logger.Warn("request rejected",
			"request_id", requestID, "status", http.StatusBadGateway,
			"parse_path", "fail", "error_class", errorClass(err))
		h.writeError(w, http.StatusBadGateway, "invalid_guard_output", "guard upstream returned an unusable verdict")
		return
	}

	rendered := qwen3guard.Render(res.Verdict)
	if rendered == "" {
		// Render refuses invalid input by returning an empty string rather
		// than a forged verdict. parse already validates, so this is a
		// defense-in-depth fail-closed branch: never 200 with empty or
		// partial content.
		h.logger.Warn("request rejected",
			"request_id", requestID, "status", http.StatusBadGateway,
			"parse_path", res.Path, "error_class", "render_refused")
		h.writeError(w, http.StatusBadGateway, "invalid_guard_output", "guard upstream returned an unusable verdict")
		return
	}
	model := req.Model
	if model == "" {
		model = "guardbridge"
	}
	response := chatCompletionResponse{
		ID:      "chatcmpl-" + requestID,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []chatChoice{{
			Index:        0,
			Message:      chatMessage{Role: "assistant", Content: rendered},
			FinishReason: "stop",
		}},
	}
	// The safety label is logged only here, after a real parse succeeded.
	h.logger.Info("request audited",
		"request_id", requestID,
		"status", http.StatusOK,
		"parse_path", res.Path,
		"safety", res.Verdict.Safety,
	)
	h.writeJSON(w, http.StatusOK, response)
}

// handleUpstreamError maps transport failures onto 5xx: timeouts become 504,
// every other transport failure (including 4xx from the upstream) becomes
// 502. We deliberately do not surface upstream status codes, headers, or
// bodies: sub2api treats any 5xx as node-unavailable and retries later, and
// an upstream 401 would disclose internal topology. The error body carries
// no Safety line, no upstream detail, and never the API key or user prompt.
func (h *Handler) handleUpstreamError(w http.ResponseWriter, requestID string, err error) {
	var te *upstream.TransportError
	if errors.As(err, &te) && te.Timeout {
		h.logger.Warn("request rejected",
			"request_id", requestID, "status", http.StatusGatewayTimeout, "reason", "upstream timeout")
		h.writeError(w, http.StatusGatewayTimeout, "upstream_unavailable", "guard upstream unavailable")
		return
	}
	h.logger.Warn("request rejected",
		"request_id", requestID, "status", http.StatusBadGateway, "reason", "upstream failure")
	h.writeError(w, http.StatusBadGateway, "upstream_unavailable", "guard upstream unavailable")
}

// authorize enforces the optional inbound bearer token. An empty configured
// token disables authentication entirely (loopback deployments). Comparison
// is constant-time to blunt timing oracles.
func (h *Handler) authorize(r *http.Request) bool {
	if h.cfg.InboundToken == "" {
		return true
	}
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	return strings.HasPrefix(auth, prefix) &&
		constantTimeEq(strings.TrimPrefix(auth, prefix), h.cfg.InboundToken)
}

func constantTimeEq(a, b string) bool {
	if len(a) != len(b) {
		// Burn comparable time on a self-compare to keep timing flat.
		_ = subtle.ConstantTimeCompare([]byte(a), []byte(a))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (h *Handler) nextRequestID() string {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("req-%d", h.requestSeq.Add(1))
	}
	return hex.EncodeToString(buf[:])
}

// inboundRequest is the subset of the OpenAI chat.completions envelope
// GuardBridge consumes. Inbound temperature, max_tokens, and seed are
// tolerated (any JSON shape) but never forwarded: the outbound request
// carries GuardBridge's own pinned sampling settings, because the inbound
// max_tokens (sub2api sends 64 for the short two-line reply) would truncate
// the JSON verdict.
type inboundRequest struct {
	Model       string           `json:"model"`
	Messages    []inboundMessage `json:"messages"`
	Stream      bool             `json:"stream"`
	MaxTokens   json.RawMessage  `json:"max_tokens"`
	Temperature json.RawMessage  `json:"temperature"`
	Seed        json.RawMessage  `json:"seed"`
}

type inboundMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// extractLastUserText walks the inbound messages last-to-first and returns
// the text of the first user message found. Content may be a plain string or
// an array of {type:"text", text:"..."} parts (joined with "\n"). A user
// message with empty, blank, or non-text content counts as no content:
// GuardBridge never invents a chunk to audit (fail-closed).
func extractLastUserText(messages []inboundMessage) (string, bool) {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role != "user" {
			continue
		}
		text, err := contentText(messages[i].Content)
		if err != nil {
			return "", false
		}
		return text, true
	}
	return "", false
}

// contentText extracts text from a message content field that is either a
// JSON string or an array of text blocks. Anything else (null, numbers,
// nested objects) yields an error rather than being coerced.
func contentText(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("message has no content")
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		// Note: JSON null unmarshals into a string without error, leaving
		// it empty — caught by the blank check below.
		if strings.TrimSpace(asString) == "" {
			return "", errors.New("message content empty")
		}
		return asString, nil
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &blocks); err == nil {
		parts := make([]string, 0, len(blocks))
		for _, block := range blocks {
			if strings.TrimSpace(block.Text) != "" {
				parts = append(parts, block.Text)
			}
		}
		if len(parts) == 0 {
			return "", errors.New("message content empty")
		}
		return strings.Join(parts, "\n"), nil
	}
	return "", errors.New("message content is neither string nor text blocks")
}

// chatCompletionResponse is the outbound OpenAI envelope GuardBridge answers
// with.
type chatCompletionResponse struct {
	ID      string       `json:"id"`
	Object  string       `json:"object"`
	Created int64        `json:"created"`
	Model   string       `json:"model"`
	Choices []chatChoice `json:"choices"`
}

type chatChoice struct {
	Index        int         `json:"index"`
	Message      chatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// openAIError is an OpenAI-style error object. Messages are static strings:
// they never embed upstream bodies, API keys, or user prompt text.
type openAIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

func (h *Handler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, struct {
		Error openAIError `json:"error"`
	}{Error: openAIError{Message: message, Type: "guardbridge_error", Code: code}})
}

func (h *Handler) writeUnauthorized(w http.ResponseWriter) {
	h.writeError(w, http.StatusUnauthorized, "invalid_api_key", "missing or invalid authorization")
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// errorClass returns a short, safe classifier for parse errors (logged
// instead of the raw error, which embeds upstream content).
func errorClass(err error) string {
	if errors.Is(err, qwen3guard.ErrInvalidVerdict) {
		return "invalid_verdict"
	}
	return "parse_error"
}

// ListenAndServe runs the HTTP server with hardened timeouts (slowloris and
// stuck-connection resistance) and shuts down gracefully on SIGINT/SIGTERM.
func ListenAndServe(cfg config.Config, h *Handler) error {
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           h.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case sig := <-stop:
		slog.Info("shutting down", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			_ = srv.Close()
			return fmt.Errorf("graceful shutdown failed: %w", err)
		}
		return nil
	}
}
