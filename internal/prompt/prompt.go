// Package prompt holds GuardBridge's system prompt for the upstream
// audit model and builds the outbound message list from it.
package prompt

import (
	_ "embed"
	"strings"
)

// Message is one entry of an OpenAI-compatible chat messages array.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

//go:embed default.txt
var defaultPrompt string

// Default returns the built-in system prompt.
func Default() string {
	return defaultPrompt
}

// Select returns the configured system prompt, or the default if the
// configured prompt is empty or whitespace-only.
func Select(configured string) string {
	if strings.TrimSpace(configured) == "" {
		return defaultPrompt
	}
	return configured
}

// OutboundMessages builds the two outbound messages for the upstream
// model: GuardBridge's system prompt followed by the audited user
// chunk. Inbound system, assistant, and tool content never reaches the
// upstream model; only the user chunk is placed in the user slot.
func OutboundMessages(systemPrompt, userChunk string) []Message {
	return []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userChunk},
	}
}
