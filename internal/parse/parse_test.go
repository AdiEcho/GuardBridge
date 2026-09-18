package parse

import (
	"errors"
	"reflect"
	"testing"

	"github.com/AdiEcho/GuardBridge/internal/qwen3guard"
)

func TestParseJSONPaths(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		wantPath   string
		wantSafety string
		wantCats   []string
	}{
		{"plain json", `{"safety":"Unsafe","categories":["Jailbreak"]}`, "json", "Unsafe", []string{"jailbreak"}},
		{"fenced json", "```json\n{\"safety\":\"Unsafe\",\"categories\":[\"Jailbreak\"]}\n```", "json", "Unsafe", []string{"jailbreak"}},
		{"bare fence", "```\n{\"safety\":\"Safe\",\"categories\":[]}\n```", "json", "Safe", []string{}},
		{"prose wrapped", "Here is my assessment:\n{\"safety\":\"Safe\",\"categories\":[]} hope that helps", "json", "Safe", []string{}},
		{"extra fields ignored", `{"safety":"Unsafe","categories":["Jailbreak"],"confidence":0.9}`, "json", "Unsafe", []string{"jailbreak"}},
		{"mixed none in array", `{"safety":"Unsafe","categories":["None","Jailbreak"]}`, "json", "Unsafe", []string{"jailbreak"}},
		{"none array", `{"safety":"Safe","categories":["None"]}`, "json", "Safe", []string{}},
		{"empty array", `{"safety":"Safe","categories":[]}`, "json", "Safe", []string{}},
		{"safety case folded", `{"safety":"sAfE","categories":["none"]}`, "json", "Safe", []string{}},
		{"alias in json", `{"safety":"controversial","categories":["personal identifiable information"]}`, "json", "Controversial", []string{"pii"}},
		{"ordered by catalog", `{"safety":"Unsafe","categories":["Jailbreak","Violent"]}`, "json", "Unsafe", []string{"violent", "jailbreak"}},
		{"plaintext direct", "Safety: Safe\nCategories: None", "plaintext", "Safe", []string{}},
		{"plaintext crlf fallback", "Safety: Safe\r\nCategories: None\r\n", "plaintext", "Safe", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.content)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tt.content, err)
			}
			if result.Path != tt.wantPath {
				t.Errorf("path = %q, want %q", result.Path, tt.wantPath)
			}
			if result.Verdict.Safety != tt.wantSafety {
				t.Errorf("safety = %q, want %q", result.Verdict.Safety, tt.wantSafety)
			}
			if !reflect.DeepEqual(result.Verdict.Categories, tt.wantCats) {
				t.Errorf("categories = %#v, want %#v", result.Verdict.Categories, tt.wantCats)
			}
			// Every accepted verdict must render the consumer contract.
			if rendered := qwen3guard.Render(result.Verdict); rendered == "" {
				t.Errorf("verdict did not render: %+v", result.Verdict)
			}
		})
	}
}

func TestParseFailClosed(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"whitespace only", "   \n\t  "},
		{"json unknown category, no plaintext", `{"safety":"Unsafe","categories":["Jailbreak","Future Risk"]}`},
		{"json missing categories", `{"safety":"Unsafe"}`},
		{"json missing safety", `{"categories":["Jailbreak"]}`},
		{"json wrong safety type", `{"safety":123,"categories":["Jailbreak"]}`},
		{"json safety null", `{"safety":null,"categories":[]}`},
		{"json unknown safety value", `{"safety":"Maybe","categories":["PII"]}`},
		{"json unbalanced", `{"safety":"Safe","categories":[]`},
		{"categories string not array", `{"safety":"Safe","categories":"Jailbreak"}`},
		{"categories wrong item type", `{"safety":"Safe","categories":[1,2]}`},
		{"braces in string value", `{"safety":"Safe","categories":["{}"]}`},
		{"brace in prose before object", "{not json at all"},
		{"no verdict markers", "The user message is fine."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.content)
			if err == nil {
				t.Fatalf("Parse(%q) = %+v, want error", tt.content, result)
			}
			if !isInvalidVerdict(err) {
				t.Errorf("error = %v, want ErrInvalidVerdict", err)
			}
		})
	}
}

func isInvalidVerdict(err error) bool { return errors.Is(err, ErrInvalidVerdict) }

func TestParseUnknownJSONCategoryFallsBackToPlaintext(t *testing.T) {
	// The JSON object has an unknown category, but the raw content
	// around it is a valid two-liner: the fallback must win and produce
	// the plaintext verdict.
	content := "Safety: Unsafe\nCategories: Jailbreak\n{\"safety\":\"Unsafe\",\"categories\":[\"Future Risk\"]}"
	result, err := Parse(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Path != "plaintext" {
		t.Errorf("path = %q, want plaintext", result.Path)
	}
	if result.Verdict.Safety != "Unsafe" {
		t.Errorf("safety = %q, want Unsafe", result.Verdict.Safety)
	}
	if !reflect.DeepEqual(result.Verdict.Categories, []string{"jailbreak"}) {
		t.Errorf("categories = %#v, want [jailbreak]", result.Verdict.Categories)
	}
}

func TestParseJSONWinsOverSurroundingPlaintext(t *testing.T) {
	// A lone valid JSON object with prose that is NOT a two-liner:
	// JSON path succeeds.
	content := "Assessment complete.\n{\"safety\":\"Controversial\",\"categories\":[\"PII\"]}\nDone."
	result, err := Parse(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Path != "json" {
		t.Errorf("path = %q, want json", result.Path)
	}
	if result.Verdict.Safety != "Controversial" {
		t.Errorf("safety = %q, want Controversial", result.Verdict.Safety)
	}
}

func TestFirstJSONObjectHandlesStringsAndNesting(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
		ok      bool
	}{
		{"plain", `x {"a":1} y`, `{"a":1}`, true},
		{"braces in string", `{"a":"}{","b":2}`, `{"a":"}{","b":2}`, true},
		{"escaped quote", `{"a":"say \"}\" ok"}`, `{"a":"say \"}\" ok"}`, true},
		{"nested", `{"a":{"b":1}}`, `{"a":{"b":1}}`, true},
		{"first of two", `{"a":1} {"b":2}`, `{"a":1}`, true},
		{"unterminated", `{"a":1`, "", false},
		{"no object", "nothing here", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := firstJSONObject(tt.content)
			if ok != tt.ok {
				t.Fatalf("firstJSONObject(%q) ok = %v, want %v", tt.content, ok, tt.ok)
			}
			if got != tt.want {
				t.Errorf("firstJSONObject(%q) = %q, want %q", tt.content, got, tt.want)
			}
		})
	}
}

func TestUnwrapFence(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"json tag", "```json\n{}\n```", "{}"},
		{"no tag", "```\n{}\n```", "{}"},
		{"not fenced", "{}", "{}"},
		{"fence with leading space", "  ```json\n{}\n```  ", "{}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unwrapFence(tt.content); got != tt.want {
				t.Errorf("unwrapFence(%q) = %q, want %q", tt.content, got, tt.want)
			}
		})
	}
}
