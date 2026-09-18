package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const minimalYAML = `
listen: ""
inbound_token: ""
upstream:
  base_url: "https://api.example.com/v1"
  api_key: "sk-test"
  model: "test-model"
  timeout_ms: 0
  max_tokens: 0
system_prompt: ""
log_level: ""
`

func TestLoadMinimalAppliesDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalYAML))
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if cfg.Listen != "127.0.0.1:8080" {
		t.Errorf("Listen = %q, want default", cfg.Listen)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
	}
	if cfg.Upstream.TimeoutMS != 15000 {
		t.Errorf("TimeoutMS = %d, want 15000", cfg.Upstream.TimeoutMS)
	}
	if cfg.Upstream.MaxTokens != 256 {
		t.Errorf("MaxTokens = %d, want 256", cfg.Upstream.MaxTokens)
	}
	if cfg.Upstream.BaseURL != "https://api.example.com/v1" {
		t.Errorf("BaseURL = %q", cfg.Upstream.BaseURL)
	}
	if cfg.Upstream.Model != "test-model" {
		t.Errorf("Model = %q", cfg.Upstream.Model)
	}
	if cfg.Upstream.Seed != nil {
		t.Errorf("Seed = %v, want nil", *cfg.Upstream.Seed)
	}
}

func TestLoadFullConfig(t *testing.T) {
	path := writeConfig(t, `
listen: "0.0.0.0:9090"
inbound_token: "secret-token"
upstream:
  base_url: "http://localhost:11434"
  api_key: ""
  model: "llama3"
  timeout_ms: 5000
  max_tokens: 1024
  seed: 42
system_prompt: "custom audit prompt"
log_level: "debug"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if cfg.Listen != "0.0.0.0:9090" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if cfg.InboundToken != "secret-token" {
		t.Errorf("InboundToken = %q", cfg.InboundToken)
	}
	if cfg.Upstream.TimeoutMS != 5000 || cfg.Upstream.MaxTokens != 1024 {
		t.Errorf("upstream = %+v", cfg.Upstream)
	}
	if cfg.Upstream.Seed == nil || *cfg.Upstream.Seed != 42 {
		t.Errorf("Seed = %v, want 42", cfg.Upstream.Seed)
	}
	if cfg.SystemPrompt != "custom audit prompt" {
		t.Errorf("SystemPrompt = %q", cfg.SystemPrompt)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q", cfg.LogLevel)
	}
}

func TestLoadInvalidConfigs(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"empty base_url", `
upstream:
  base_url: ""
  model: "m"
`},
		{"bad scheme", `
upstream:
  base_url: "ftp://api.example.com"
  model: "m"
`},
		{"base_url with query", `
upstream:
  base_url: "https://api.example.com?token=x"
  model: "m"
`},
		{"base_url with fragment", `
upstream:
  base_url: "https://api.example.com#frag"
  model: "m"
`},
		{"base_url with user info", `
upstream:
  base_url: "https://user:pass@api.example.com"
  model: "m"
`},
		{"base_url without host", `
upstream:
  base_url: "https://"
  model: "m"
`},
		{"missing model", `
upstream:
  base_url: "https://api.example.com"
`},
		{"timeout too small", `
upstream:
  base_url: "https://api.example.com"
  model: "m"
  timeout_ms: 99
`},
		{"timeout too large", `
upstream:
  base_url: "https://api.example.com"
  model: "m"
  timeout_ms: 30001
`},
		{"max_tokens too small", `
upstream:
  base_url: "https://api.example.com"
  model: "m"
  max_tokens: 63
`},
		{"max_tokens too large", `
upstream:
  base_url: "https://api.example.com"
  model: "m"
  max_tokens: 8193
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, tt.yaml)); err == nil {
				t.Fatalf("Load succeeded for %s, want error", tt.name)
			}
		})
	}
}

func TestLoadBoundaryValues(t *testing.T) {
	path := writeConfig(t, `
upstream:
  base_url: "https://api.example.com"
  model: "m"
  timeout_ms: 100
  max_tokens: 8192
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if cfg.Upstream.TimeoutMS != 100 || cfg.Upstream.MaxTokens != 8192 {
		t.Errorf("boundary values rejected: %+v", cfg.Upstream)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Fatal("Load succeeded for missing file, want error")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	path := writeConfig(t, "listen: [unclosed")
	if _, err := Load(path); err == nil {
		t.Fatal("Load succeeded for invalid YAML, want error")
	}
}
