package fingerprint

// NameInference is a hypothesis about device identity from names or user rules—not protocol-verified L4 fact.
// Stored in hosts.fingerprint_blob alongside signals (see FINGERPRINT-PLAN.md L5-adjacent hints).
//
// Optional internet-assisted hints use source "web_llm" only when enabled in Diagnostics with a
// user-supplied API key (OpenAI or Anthropic); hostname fragments are sent, not IPs.
type NameInference struct {
	// Source is local_rule | user_alias_mac | user_alias_hostname | web_llm
	Source string `json:"source"`
	// Kind is family | product_hint | user_label
	Kind string `json:"kind"`
	// Confidence is high | medium | low
	Confidence string `json:"confidence"`
	// Input is the substring, MAC prefix, field that matched, or for web_llm: "openai" | "claude".
	Input string `json:"input"`
	// Text is the human-readable suggestion shown in UI.
	Text string `json:"text"`
	// RuleID is set for local_rule (stable id for tests/docs); empty for user aliases.
	RuleID string `json:"rule_id,omitempty"`
}
