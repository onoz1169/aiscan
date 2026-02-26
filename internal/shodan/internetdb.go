// Package shodan provides a client for Shodan's InternetDB API.
// No API key required. Free for non-commercial use.
// https://internetdb.shodan.io
package shodan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const internetDBURL = "https://internetdb.shodan.io/"

// InternetDBResult is the response from Shodan's InternetDB endpoint.
type InternetDBResult struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Hostnames []string `json:"hostnames"`
	CPEs      []string `json:"cpes"`
	Vulns     []string `json:"vulns"` // CVE IDs
	Tags      []string `json:"tags"`
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

// QueryInternetDB fetches Shodan's InternetDB record for the given IP.
// Returns nil, nil if the IP is not in Shodan's database (404).
func QueryInternetDB(ip string) (*InternetDBResult, error) {
	resp, err := httpClient.Get(internetDBURL + ip)
	if err != nil {
		return nil, fmt.Errorf("internetdb request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // IP not in Shodan database
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("internetdb: HTTP %d", resp.StatusCode)
	}

	var result InternetDBResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode internetdb response: %w", err)
	}
	return &result, nil
}
