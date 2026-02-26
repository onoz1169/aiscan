// Package osv provides a client for the OSV (Open Source Vulnerability) API.
// No API key required. https://osv.dev/docs/
package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const osvQueryURL = "https://api.osv.dev/v1/query"

// ServiceMapping maps nmap product names to OSV (ecosystem, package) pairs.
var ServiceMapping = map[string]struct{ Ecosystem, Package string }{
	"nginx":          {"Debian", "nginx"},
	"apache":         {"Debian", "apache2"},
	"apache httpd":   {"Debian", "apache2"},
	"openssh":        {"Debian", "openssh"},
	"redis":          {"Debian", "redis"},
	"postgresql":     {"Debian", "postgresql"},
	"mysql":          {"Debian", "mysql-server"},
	"mariadb":        {"Debian", "mariadb"},
	"mongodb":        {"Debian", "mongodb"},
	"openssl":        {"Debian", "openssl"},
	"php":            {"Debian", "php"},
	"proftpd":        {"Debian", "proftpd"},
	"vsftpd":         {"Debian", "vsftpd"},
	"postfix":        {"Debian", "postfix"},
	"exim":           {"Debian", "exim4"},
	"samba":          {"Debian", "samba"},
	"bind":           {"Debian", "bind9"},
	"memcached":      {"Debian", "memcached"},
	"rabbitmq":       {"Debian", "rabbitmq-server"},
	"jenkins":        {"Maven", "org.jenkins-ci.main:jenkins-core"},
	"elasticsearch":  {"Maven", "org.elasticsearch:elasticsearch"},
}

// Vulnerability is a simplified OSV vulnerability record.
type Vulnerability struct {
	ID       string   // OSV ID (e.g. "GHSA-xxx" or "CVE-2024-...")
	Aliases  []string // CVE IDs and other aliases
	Summary  string
	Severity string  // CRITICAL / HIGH / MEDIUM / LOW
	Score    float64 // CVSS base score
	Fixed    string  // Fixed version, if known
}

type osvQueryRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version,omitempty"`
}

type osvResponse struct {
	Vulns []struct {
		ID      string   `json:"id"`
		Aliases []string `json:"aliases"`
		Summary string   `json:"summary"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		Affected []struct {
			Ranges []struct {
				Type   string `json:"type"`
				Events []struct {
					Introduced string `json:"introduced,omitempty"`
					Fixed      string `json:"fixed,omitempty"`
				} `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	} `json:"vulns"`
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Query looks up vulnerabilities for the given service product and version.
// Returns nil, nil if no mapping is found for the product.
func Query(product, version string) ([]Vulnerability, error) {
	key := strings.ToLower(strings.TrimSpace(product))
	mapping, ok := ServiceMapping[key]
	if !ok {
		// Try prefix match for products like "nginx 1.18.0"
		for k, v := range ServiceMapping {
			if strings.HasPrefix(key, k) {
				mapping = v
				ok = true
				break
			}
		}
	}
	if !ok {
		return nil, nil // no ecosystem mapping for this product
	}

	req := osvQueryRequest{Version: version}
	req.Package.Name = mapping.Package
	req.Package.Ecosystem = mapping.Ecosystem

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal osv query: %w", err)
	}

	resp, err := httpClient.Post(osvQueryURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: HTTP %d", resp.StatusCode)
	}

	var osvResp osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("decode osv response: %w", err)
	}

	var results []Vulnerability
	for _, v := range osvResp.Vulns {
		vuln := Vulnerability{
			ID:      v.ID,
			Aliases: v.Aliases,
			Summary: v.Summary,
		}

		// Extract CVSS score from severity field
		for _, s := range v.Severity {
			if s.Type == "CVSS_V3" {
				vuln.Score = parseCVSSScore(s.Score)
				vuln.Severity = cvssScoreToSeverity(vuln.Score)
				break
			}
		}
		if vuln.Severity == "" && len(v.Severity) > 0 {
			// Fall back to first severity entry
			vuln.Score = parseCVSSScore(v.Severity[0].Score)
			vuln.Severity = cvssScoreToSeverity(vuln.Score)
		}

		// Extract fix version from ranges
		for _, affected := range v.Affected {
			for _, r := range affected.Ranges {
				for _, e := range r.Events {
					if e.Fixed != "" {
						vuln.Fixed = e.Fixed
						break
					}
				}
				if vuln.Fixed != "" {
					break
				}
			}
			if vuln.Fixed != "" {
				break
			}
		}

		results = append(results, vuln)
	}

	return results, nil
}

// parseCVSSScore parses a CVSS vector string to extract the base score.
// CVSS vectors like "CVSS:3.1/AV:N/AC:L/..." don't directly contain the score;
// OSV sometimes puts the numeric score directly in this field.
func parseCVSSScore(s string) float64 {
	// OSV severity Score field may be a vector string or a numeric string
	var score float64
	fmt.Sscanf(s, "%f", &score)
	return score
}

func cvssScoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return ""
	}
}
