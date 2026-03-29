package fingerprint

// NameInference is a hypothesis about device identity from names or user rules—not protocol-verified L4 fact.
// Stored in hosts.fingerprint_blob alongside signals (see FINGERPRINT-PLAN.md L5-adjacent hints).
//
// Web search / LLM enrichment is intentionally out of scope for the default product (privacy, trust).
// A future opt-in mode could add source "web_lookup" with rate limits, explicit consent in setup,
// and UI copy that third parties receive queried strings—see product plan; not implemented here.
type NameInference struct {
	// Source is local_rule | user_alias_mac | user_alias_hostname
	Source string `json:"source"`
	// Kind is family | product_hint | user_label
	Kind string `json:"kind"`
	// Confidence is high | medium | low
	Confidence string `json:"confidence"`
	// Input is the substring, MAC prefix, or field that matched (for transparency).
	Input string `json:"input"`
	// Text is the human-readable suggestion shown in UI.
	Text string `json:"text"`
	// RuleID is set for local_rule (stable id for tests/docs); empty for user aliases.
	RuleID string `json:"rule_id,omitempty"`
}
