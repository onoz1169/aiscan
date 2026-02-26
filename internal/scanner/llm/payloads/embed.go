package payloads

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed *.json
var FS embed.FS

// PayloadFile represents a loaded payload JSON file.
type PayloadFile struct {
	Category string   `json:"category"`
	OWASP    string   `json:"owasp"`
	Payloads []string `json:"payloads"`
}

// Load reads all payload JSON files from the embedded filesystem.
func Load() (map[string]PayloadFile, error) {
	entries, err := FS.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("read payloads dir: %w", err)
	}

	result := make(map[string]PayloadFile)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := FS.ReadFile(entry.Name())
		if err != nil {
			continue
		}
		var pf PayloadFile
		if err := json.Unmarshal(data, &pf); err != nil {
			continue
		}
		result[pf.Category] = pf
	}
	return result, nil
}
