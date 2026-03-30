package fingerprint

import "encoding/json"

// InferencesFromFingerprintBlob returns name inferences embedded in persisted fingerprint JSON.
func InferencesFromFingerprintBlob(raw []byte) []NameInference {
	if len(raw) == 0 {
		return nil
	}
	var stub struct {
		Inferences []NameInference `json:"inferences"`
	}
	if err := json.Unmarshal(raw, &stub); err != nil {
		return nil
	}
	return stub.Inferences
}

// WebLLMInferencesFromBlob returns only web_llm rows from persisted fingerprint JSON.
// Used to avoid repeat API calls when a host already has a stored LLM name hint.
func WebLLMInferencesFromBlob(raw []byte) []NameInference {
	all := InferencesFromFingerprintBlob(raw)
	if len(all) == 0 {
		return nil
	}
	var out []NameInference
	for _, inf := range all {
		if inf.Source == "web_llm" {
			out = append(out, inf)
		}
	}
	return out
}
