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
