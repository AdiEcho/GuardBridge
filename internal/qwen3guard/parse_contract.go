package qwen3guard

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidVerdict is the sentinel error for content that cannot be
// parsed into a valid verdict. GuardBridge fails closed on it: an
// invalid verdict is never rendered as a Safety line.
var ErrInvalidVerdict = errors.New("qwen3guard: invalid verdict")

// Verdict is the normalized audit result.
type Verdict struct {
	Safety     string   // canonical "Safe"|"Unsafe"|"Controversial"
	Categories []string // canonical scanner IDs, ordered by AllScannerIDs
}

// ParseLines parses Qwen3Guard two-line plaintext verdicts. Line rules
// mirror the sub2api consumer (ParseQwen3Guard): "safety:" and
// "categories:" prefixes match case-insensitively, duplicate fields
// fail, missing fields fail, unknown safety values fail, and auxiliary
// lines such as "Refusal:" are ignored. "None" and "N/A" category
// entries mean an empty set. CRLF is normalized to LF first, lines are
// trimmed, and empty lines are skipped.
//
// Deviation from sub2api (deliberate): unknown category names fail the
// parse instead of being recorded as opaque "unknown:" hashes.
// GuardBridge only ever renders official labels, so an unknown name
// means the model produced non-canonical output; rejecting it
// guarantees the renderer can never emit an unknown label.
func ParseLines(content string) (Verdict, error) {
	var safety string
	var categoryLine string
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "safety:"):
			if safety != "" {
				return Verdict{}, fmt.Errorf("%w: duplicate safety line", ErrInvalidVerdict)
			}
			safety = strings.TrimSpace(line[len("safety:"):])
		case strings.HasPrefix(lower, "categories:"):
			if categoryLine != "" {
				return Verdict{}, fmt.Errorf("%w: duplicate categories line", ErrInvalidVerdict)
			}
			categoryLine = strings.TrimSpace(line[len("categories:"):])
		default:
			// Auxiliary Guard fields such as Refusal do not affect the verdict.
		}
	}
	safetyValue, ok := NormalizeSafety(safety)
	if !ok {
		return Verdict{}, fmt.Errorf("%w: missing or unknown safety value", ErrInvalidVerdict)
	}
	if categoryLine == "" {
		return Verdict{}, fmt.Errorf("%w: missing categories line", ErrInvalidVerdict)
	}
	categories, err := NormalizeCategories(strings.Split(categoryLine, ","))
	if err != nil {
		return Verdict{}, err
	}
	return Verdict{Safety: safetyValue, Categories: categories}, nil
}

// NormalizeCategories converts raw category names into the canonical
// verdict form: entries are trimmed, empty/"None"/"N/A" entries
// (case-insensitive) are skipped, names go through NormalizeCategory,
// unknown names are rejected, and the result is deduplicated and
// ordered by AllScannerIDs. It is shared by the plaintext and JSON
// parsers so both paths accept exactly the same category spellings.
func NormalizeCategories(values []string) ([]string, error) {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || strings.EqualFold(value, "none") || strings.EqualFold(value, "n/a") {
			continue
		}
		category := NormalizeCategory(value)
		if _, known := ScannerCatalog[category]; !known {
			return nil, fmt.Errorf("%w: unknown category", ErrInvalidVerdict)
		}
		set[category] = struct{}{}
	}
	ordered := make([]string, 0, len(set))
	for _, id := range AllScannerIDs {
		if _, ok := set[id]; ok {
			ordered = append(ordered, id)
		}
	}
	return ordered, nil
}
