// Package parse extracts a qwen3guard verdict from upstream model
// output. It tries strict JSON first, then the two-line plaintext
// fallback, and fails closed with ErrInvalidVerdict when neither path
// produces a valid verdict.
package parse

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/AdiEcho/GuardBridge/internal/qwen3guard"
)

// ErrInvalidVerdict reports that the content contained no valid verdict
// on either the JSON or the plaintext path. GuardBridge fails closed on
// this error and never renders a Safety line for it.
var ErrInvalidVerdict = qwen3guard.ErrInvalidVerdict

// Result reports which path produced the verdict.
type Result struct {
	Verdict qwen3guard.Verdict
	Path    string // "json" or "plaintext"
}

const (
	pathJSON      = "json"
	pathPlaintext = "plaintext"
)

// verdictJSON is the strict wire schema; unknown fields are ignored by
// encoding/json. The fields are pointers so that a missing key is
// distinguishable from a present-but-empty value: "categories":[] is a
// valid empty set, whereas an absent "categories" key fails the JSON
// path.
type verdictJSON struct {
	Safety     *string   `json:"safety"`
	Categories *[]string `json:"categories"`
}

// Parse extracts a verdict from upstream model output. It first looks
// for a JSON object with "safety" and "categories" keys (unwrapping a
// markdown fence if present, and extracting the first balanced object
// from surrounding prose); if that fails for any reason — including an
// unknown category — it falls back to the Qwen3Guard two-line plaintext
// parser over the raw content. When both paths fail it returns
// ErrInvalidVerdict.
func Parse(content string) (Result, error) {
	if result, err := parseJSON(content); err == nil {
		return result, nil
	}
	// The fallback parses the raw content, never the extracted JSON.
	if verdict, err := qwen3guard.ParseLines(content); err == nil {
		return Result{Verdict: verdict, Path: pathPlaintext}, nil
	}
	return Result{}, fmt.Errorf("%w: no valid verdict in content", ErrInvalidVerdict)
}

// parseJSON implements the strict JSON path. It returns an error for
// any deviation: no JSON object, unbalanced braces, missing keys, wrong
// types, a non-canonical safety value, or an unknown category.
func parseJSON(content string) (Result, error) {
	if strings.TrimSpace(content) == "" {
		return Result{}, fmt.Errorf("%w: empty content", ErrInvalidVerdict)
	}
	object, ok := firstJSONObject(unwrapFence(content))
	if !ok {
		return Result{}, fmt.Errorf("%w: no JSON object", ErrInvalidVerdict)
	}
	var raw verdictJSON
	if err := json.Unmarshal([]byte(object), &raw); err != nil {
		return Result{}, fmt.Errorf("%w: invalid verdict JSON: %v", ErrInvalidVerdict, err)
	}
	if raw.Safety == nil || raw.Categories == nil {
		return Result{}, fmt.Errorf("%w: safety and categories keys are both required", ErrInvalidVerdict)
	}
	safety, ok := qwen3guard.NormalizeSafety(*raw.Safety)
	if !ok {
		return Result{}, fmt.Errorf("%w: missing or unknown safety value", ErrInvalidVerdict)
	}
	categories, err := qwen3guard.NormalizeCategories(*raw.Categories)
	if err != nil {
		return Result{}, fmt.Errorf("%w: invalid categories: %v", ErrInvalidVerdict, err)
	}
	return Result{Verdict: qwen3guard.Verdict{Safety: safety, Categories: categories}, Path: pathJSON}, nil
}

// unwrapFence returns the inner body of a markdown code fence if the
// content starts with ``` (optionally followed by a language tag such
// as json); otherwise it returns the content unchanged.
func unwrapFence(content string) string {
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, "```") {
		return content
	}
	body := strings.TrimPrefix(trimmed, "```")
	// Drop the opening tag (e.g. "json") up to the end of the first line.
	if newline := strings.IndexByte(body, '\n'); newline >= 0 {
		body = body[newline+1:]
	} else {
		body = strings.TrimLeft(body, " \t")
	}
	body = strings.TrimSuffix(strings.TrimSpace(body), "```")
	return strings.TrimSpace(body)
}

// firstJSONObject returns the first balanced {...} substring, treating
// the content as raw text with JSON string semantics: braces inside
// quoted strings do not count toward nesting, and backslash escapes
// are honored inside strings.
func firstJSONObject(content string) (string, bool) {
	start := strings.IndexByte(content, '{')
	if start < 0 {
		return "", false
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(content); i++ {
		c := content[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return content[start : i+1], true
			}
		}
	}
	return "", false
}
