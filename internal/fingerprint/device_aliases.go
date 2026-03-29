package fingerprint

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// DeviceAliasesFile is optional JSON next to the SQLite DB (see README).
type DeviceAliasesFile struct {
	HostnameSubstrings map[string]string `json:"hostname_substrings"`
	MacPrefixes        map[string]string `json:"mac_prefixes"`
}

// AliasesPathNextToDB returns the path to device_aliases.json in the same directory as dbPath.
func AliasesPathNextToDB(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "device_aliases.json")
}

// LoadDeviceAliases reads path. Missing file yields an empty config, nil error.
// Invalid JSON returns an error.
func LoadDeviceAliases(path string) (*DeviceAliasesFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &DeviceAliasesFile{
				HostnameSubstrings: map[string]string{},
				MacPrefixes:        map[string]string{},
			}, nil
		}
		return nil, err
	}
	var f DeviceAliasesFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if f.HostnameSubstrings == nil {
		f.HostnameSubstrings = map[string]string{}
	}
	if f.MacPrefixes == nil {
		f.MacPrefixes = map[string]string{}
	}
	return &f, nil
}
