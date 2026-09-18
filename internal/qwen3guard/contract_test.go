package qwen3guard

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestCatalogMatchesAllScannerIDs(t *testing.T) {
	if len(AllScannerIDs) != 9 {
		t.Fatalf("AllScannerIDs has %d entries, want 9", len(AllScannerIDs))
	}
	seen := make(map[string]bool, len(AllScannerIDs))
	for _, id := range AllScannerIDs {
		if seen[id] {
			t.Fatalf("duplicate scanner ID %q", id)
		}
		seen[id] = true
		definition, ok := ScannerCatalog[id]
		if !ok {
			t.Fatalf("scanner ID %q missing from ScannerCatalog", id)
		}
		if definition.ID != id || definition.Label == "" || definition.LabelZH == "" {
			t.Fatalf("incomplete definition for %q: %+v", id, definition)
		}
	}
	if len(ScannerCatalog) != len(AllScannerIDs) {
		t.Fatalf("ScannerCatalog has %d entries, want %d", len(ScannerCatalog), len(AllScannerIDs))
	}
}

// Golden cases ported from the sub2api consumer's tests, plus the
// deliberate stricter rules (unknown categories fail).
func TestParseLinesGolden(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		wantSafety string
		wantCats   []string
		wantErr    bool
	}{
		{"safe", "Safety: Safe\nCategories: None", "Safe", []string{}, false},
		{"controversial", "Safety: Controversial\nCategories: Violent", "Controversial", []string{"violent"}, false},
		{"unsafe", "Safety: Unsafe\nCategories: Jailbreak", "Unsafe", []string{"jailbreak"}, false},
		{"extra explanation ignored", "Safety: Safe\nCategories: None\nThis is safe", "Safe", []string{}, false},
		{"refusal ignored", "Safety: Unsafe\nCategories: Jailbreak\nRefusal: No", "Unsafe", []string{"jailbreak"}, false},
		{"crlf", "Safety: Safe\r\nCategories: None\r\n", "Safe", []string{}, false},
		{"mixed none", "Safety: Unsafe\nCategories: None, Jailbreak", "Unsafe", []string{"jailbreak"}, false},
		{"n/a skipped", "Safety: Safe\nCategories: N/A", "Safe", []string{}, false},
		{"reordered by catalog", "Safety: Unsafe\nCategories: Jailbreak, Violent", "Unsafe", []string{"violent", "jailbreak"}, false},
		{"deduplicated", "Safety: Unsafe\nCategories: Violent, violence", "Unsafe", []string{"violent"}, false},
		{"duplicate safety", "Safety: Safe\nSafety: Safe", "", nil, true},
		{"duplicate categories", "Safety: Safe\nCategories: None\nCategories: PII", "", nil, true},
		{"missing categories", "Safety: Safe\n", "", nil, true},
		{"missing safety", "Categories: PII", "", nil, true},
		{"unknown safety", "Safety: Maybe\nCategories: PII", "", nil, true},
		{"unknown category fails closed", "Safety: Unsafe\nCategories: Future Risk", "", nil, true},
		{"empty content", "", "", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict, err := ParseLines(tt.content)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseLines(%q) = %+v, want error", tt.content, verdict)
				}
				if !errors.Is(err, ErrInvalidVerdict) {
					t.Fatalf("ParseLines(%q) error = %v, want ErrInvalidVerdict", tt.content, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseLines(%q) unexpected error: %v", tt.content, err)
			}
			if verdict.Safety != tt.wantSafety {
				t.Errorf("safety = %q, want %q", verdict.Safety, tt.wantSafety)
			}
			if !reflect.DeepEqual(verdict.Categories, tt.wantCats) {
				t.Errorf("categories = %#v, want %#v", verdict.Categories, tt.wantCats)
			}
		})
	}
}

func TestParseLinesAllNineOfficialCategories(t *testing.T) {
	official := "Violent, Non-violent Illegal Acts, Sexual Content or Sexual Acts, PII, Suicide & Self-Harm, Unethical Acts, Politically Sensitive Topics, Copyright Violation, Jailbreak"
	verdict, err := ParseLines("Safety: Unsafe\nCategories: " + official)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Safety != "Unsafe" {
		t.Errorf("safety = %q, want Unsafe", verdict.Safety)
	}
	if !reflect.DeepEqual(verdict.Categories, AllScannerIDs) {
		t.Fatalf("categories = %#v, want %#v", verdict.Categories, AllScannerIDs)
	}
}

func TestRenderParseLinesRoundTripAllNine(t *testing.T) {
	want := "Safety: Unsafe\nCategories: Violent, Non-violent Illegal Acts, Sexual Content or Sexual Acts, PII, Suicide & Self-Harm, Unethical Acts, Politically Sensitive Topics, Copyright Violation, Jailbreak"
	got := Render(Verdict{Safety: "Unsafe", Categories: AllScannerIDs})
	if got != want {
		t.Fatalf("Render() = %q, want %q", got, want)
	}
	verdict, err := ParseLines(got)
	if err != nil {
		t.Fatalf("ParseLines(Render()) error: %v", err)
	}
	if verdict.Safety != "Unsafe" {
		t.Errorf("safety = %q, want Unsafe", verdict.Safety)
	}
	if !reflect.DeepEqual(verdict.Categories, AllScannerIDs) {
		t.Errorf("categories = %#v, want %#v", verdict.Categories, AllScannerIDs)
	}
}

func TestRenderParseLinesIdempotentOnCanonicalText(t *testing.T) {
	canonical := []string{
		"Safety: Safe\nCategories: None",
		"Safety: Controversial\nCategories: Violent",
		"Safety: Unsafe\nCategories: Jailbreak",
		"Safety: Unsafe\nCategories: Violent, Non-violent Illegal Acts, Sexual Content or Sexual Acts, PII, Suicide & Self-Harm, Unethical Acts, Politically Sensitive Topics, Copyright Violation, Jailbreak",
	}
	for _, text := range canonical {
		verdict, err := ParseLines(text)
		if err != nil {
			t.Fatalf("ParseLines(%q) error: %v", text, err)
		}
		if got := Render(verdict); got != text {
			t.Errorf("Render(ParseLines(%q)) = %q, want identity", text, got)
		}
	}
}

func TestRenderNeverEmitsRefusal(t *testing.T) {
	verdict, err := ParseLines("Safety: Unsafe\nCategories: Jailbreak\nRefusal: No")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := Render(verdict); strings.Contains(got, "Refusal") {
		t.Fatalf("Render() emitted Refusal: %q", got)
	}
}

func TestRenderRejectsInvalidVerdicts(t *testing.T) {
	tests := []Verdict{
		{Safety: "safe", Categories: nil},                     // non-canonical case
		{Safety: "Maybe", Categories: nil},                    // unknown safety
		{Safety: "", Categories: nil},                         // missing safety
		{Safety: "Safe", Categories: []string{"future_risk"}}, // unknown category ID
	}
	for _, verdict := range tests {
		if got := Render(verdict); got != "" {
			t.Errorf("Render(%+v) = %q, want empty string (fail closed)", verdict, got)
		}
	}
}

func TestNormalizeCategoryAliases(t *testing.T) {
	aliases := map[string]string{
		"violence":                          "violent",
		"non_violent_illegal_acts":          "non_violent_illegal_acts",
		"sexual":                            "sexual_content_or_sexual_acts",
		"personal identifiable information": "pii",
		"suicide/self harm":                 "suicide_and_self_harm",
		"unethical":                         "unethical_acts",
		"political":                         "politically_sensitive_topics",
		"copyright":                         "copyright_violation",
		"prompt injection":                  "jailbreak",
	}
	for alias, want := range aliases {
		if got := NormalizeCategory(alias); got != want {
			t.Errorf("NormalizeCategory(%q) = %q, want %q", alias, got, want)
		}
	}
	// Official labels must normalize back to their own IDs so rendered
	// output round-trips through the consumer.
	for _, id := range AllScannerIDs {
		label := ScannerCatalog[id].Label
		if got := NormalizeCategory(label); got != id {
			t.Errorf("NormalizeCategory(label %q) = %q, want %q", label, got, id)
		}
	}
	// Unknown names keep their underscored form and are rejected later.
	if got := NormalizeCategory("Future Risk"); got != "future_risk" {
		t.Errorf("NormalizeCategory(%q) = %q, want future_risk", "Future Risk", got)
	}
}

func TestNormalizeSafety(t *testing.T) {
	valid := map[string]string{
		"Safe": "Safe", "safe": "Safe", "  SAFE ": "Safe",
		"Unsafe": "Unsafe", "UNSAFE": "Unsafe",
		"Controversial": "Controversial", "controversial": "Controversial",
	}
	for value, want := range valid {
		got, ok := NormalizeSafety(value)
		if !ok || got != want {
			t.Errorf("NormalizeSafety(%q) = (%q, %v), want (%q, true)", value, got, ok, want)
		}
	}
	for _, value := range []string{"", " ", "Maybe", "safe-ish", "saf"} {
		if got, ok := NormalizeSafety(value); ok {
			t.Errorf("NormalizeSafety(%q) = (%q, true), want false", value, got)
		}
	}
}
