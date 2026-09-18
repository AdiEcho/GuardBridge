// Package qwen3guard ports the verdict contract of sub2api's Qwen3Guard
// consumer: the nine official scanner categories, their aliases, and the
// two-line plaintext format "Safety: <X>\nCategories: <Y>" that the
// consumer's ParseQwen3Guard accepts.
package qwen3guard

import "strings"

// ScannerDefinition describes one official audit category.
type ScannerDefinition struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	LabelZH string `json:"label_zh"`
}

// AllScannerIDs lists the nine official scanner IDs in canonical order.
var AllScannerIDs = []string{
	"violent",
	"non_violent_illegal_acts",
	"sexual_content_or_sexual_acts",
	"pii",
	"suicide_and_self_harm",
	"unethical_acts",
	"politically_sensitive_topics",
	"copyright_violation",
	"jailbreak",
}

// ScannerCatalog maps each scanner ID to its official definition.
var ScannerCatalog = map[string]ScannerDefinition{
	"violent":                       {ID: "violent", Label: "Violent", LabelZH: "暴力"},
	"non_violent_illegal_acts":      {ID: "non_violent_illegal_acts", Label: "Non-violent Illegal Acts", LabelZH: "非暴力违法行为"},
	"sexual_content_or_sexual_acts": {ID: "sexual_content_or_sexual_acts", Label: "Sexual Content or Sexual Acts", LabelZH: "性内容或性行为"},
	"pii":                           {ID: "pii", Label: "PII", LabelZH: "个人敏感信息"},
	"suicide_and_self_harm":         {ID: "suicide_and_self_harm", Label: "Suicide & Self-Harm", LabelZH: "自杀与自残"},
	"unethical_acts":                {ID: "unethical_acts", Label: "Unethical Acts", LabelZH: "不道德行为"},
	"politically_sensitive_topics":  {ID: "politically_sensitive_topics", Label: "Politically Sensitive Topics", LabelZH: "政治敏感话题"},
	"copyright_violation":           {ID: "copyright_violation", Label: "Copyright Violation", LabelZH: "版权侵权"},
	"jailbreak":                     {ID: "jailbreak", Label: "Jailbreak", LabelZH: "越狱攻击"},
}

// categoryAliases maps normalized category names to canonical scanner
// IDs, copied from the sub2api consumer.
var categoryAliases = map[string]string{
	"violent": "violent", "violence": "violent",
	"non violent illegal acts": "non_violent_illegal_acts", "non-violent illegal acts": "non_violent_illegal_acts",
	"sexual content or sexual acts": "sexual_content_or_sexual_acts", "sexual": "sexual_content_or_sexual_acts",
	"pii": "pii", "personal identifying information": "pii", "personal identifiable information": "pii",
	"suicide self harm": "suicide_and_self_harm", "suicide and self harm": "suicide_and_self_harm", "suicide & self-harm": "suicide_and_self_harm",
	"unethical acts": "unethical_acts", "unethical": "unethical_acts",
	"politically sensitive topics": "politically_sensitive_topics", "political": "politically_sensitive_topics",
	"copyright violation": "copyright_violation", "copyright": "copyright_violation",
	"jailbreak": "jailbreak", "prompt injection": "jailbreak",
}

// NormalizeCategory maps a raw category name to a canonical scanner ID,
// mirroring the sub2api consumer exactly: lowercase, trim, underscores
// and the separators "/", "-", "–", "—" become spaces, "&" becomes
// " and ", whitespace runs collapse to single spaces, known aliases
// resolve to their ID, and anything else keeps its underscored form
// (unknown unless present in ScannerCatalog).
func NormalizeCategory(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.NewReplacer("_", " ", "&", " and ", "/", " ", "-", " ", "–", " ", "—", " ").Replace(normalized)
	normalized = strings.Join(strings.Fields(normalized), " ")
	if canonical, ok := categoryAliases[normalized]; ok {
		return canonical
	}
	return strings.ReplaceAll(normalized, " ", "_")
}

// NormalizeSafety maps a raw safety value to its canonical form. It
// reports false unless the value equals (case-insensitively, after
// trimming) one of Safe, Unsafe, or Controversial.
func NormalizeSafety(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "safe":
		return "Safe", true
	case "unsafe":
		return "Unsafe", true
	case "controversial":
		return "Controversial", true
	default:
		return "", false
	}
}
