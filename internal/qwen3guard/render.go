package qwen3guard

import "strings"

// Render formats a Verdict as the exact two-line plaintext that the
// sub2api consumer (ParseQwen3Guard) and ParseLines accept:
//
//	Safety: <X>\nCategories: <Y>
//
// Categories are rendered as their official Labels joined with ", ";
// an empty set renders "None". Render never emits a Refusal line.
//
// Render validates its input: Safety must already be canonical and
// every category must be a known scanner ID. On invalid input it
// returns an empty string — never a forged verdict — and the caller
// must treat that as a fail-closed condition.
func Render(v Verdict) string {
	switch v.Safety {
	case "Safe", "Unsafe", "Controversial":
	default:
		return ""
	}
	labels := make([]string, 0, len(v.Categories))
	for _, id := range v.Categories {
		definition, ok := ScannerCatalog[id]
		if !ok {
			return ""
		}
		labels = append(labels, definition.Label)
	}
	categories := strings.Join(labels, ", ")
	if categories == "" {
		categories = "None"
	}
	return "Safety: " + v.Safety + "\nCategories: " + categories
}
