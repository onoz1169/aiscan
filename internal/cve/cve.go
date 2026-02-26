// Package cve provides a client for the NVD (National Vulnerability Database) API v2.
// API docs: https://nvd.nist.gov/developers/vulnerabilities
package cve

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	nvdBaseURL     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	requestTimeout = 15 * time.Second
	// NVD rate limits: 5 req/30s without key, 50 req/30s with key.
	// 700ms between requests stays well within the authenticated limit.
	requestDelay = 700 * time.Millisecond
)

// Result holds a single CVE finding.
type Result struct {
	ID          string
	Description string
	Score       float64 // CVSS v3 base score (0.0 if unavailable)
	Severity    string  // CRITICAL / HIGH / MEDIUM / LOW
	Published   string  // YYYY-MM-DD
	URL         string
}

// nvdEnvelope mirrors the NVD API v2 JSON envelope.
type nvdEnvelope struct {
	ResultsPerPage int `json:"resultsPerPage"`
	Vulnerabilities []struct {
		Cve struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					Type     string `json:"type"`
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CvssMetricV30 []struct {
					Type     string `json:"type"`
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
				CvssMetricV2 []struct {
					Type     string `json:"type"`
					CvssData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// Client is an NVD API v2 client.
type Client struct {
	apiKey string
	http   *http.Client
	last   time.Time // time of last request (for rate limiting)
}

// New creates an NVD API client. apiKey may be empty (lower rate limit).
func New(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		http:   &http.Client{Timeout: requestTimeout},
	}
}

// Lookup queries the NVD for CVEs matching the given service product and version.
// Returns at most maxResults results, sorted by CVSS score descending.
// Only returns CVEs with CVSS score >= minScore (use 0 for all).
func (c *Client) Lookup(product, version string, maxResults int, minScore float64) ([]Result, error) {
	if product == "" {
		return nil, nil
	}

	// Rate limiting: wait between requests
	if elapsed := time.Since(c.last); elapsed < requestDelay {
		time.Sleep(requestDelay - elapsed)
	}
	c.last = time.Now()

	keyword := strings.TrimSpace(product)
	if version != "" {
		keyword += " " + version
	}

	u, _ := url.Parse(nvdBaseURL)
	q := u.Query()
	q.Set("keywordSearch", keyword)
	q.Set("resultsPerPage", "10")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("NVD API: invalid API key")
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("NVD API: rate limited (429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API: HTTP %d", resp.StatusCode)
	}

	var env nvdEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	var results []Result
	for _, v := range env.Vulnerabilities {
		cve := v.Cve

		// English description
		desc := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}

		// CVSS score: prefer v3.1 Primary, then v3.1 Secondary, then v3.0, then v2
		score, severity := extractCVSS(cve.Metrics.CvssMetricV31, cve.Metrics.CvssMetricV30, cve.Metrics.CvssMetricV2)

		if score < minScore {
			continue
		}

		pub := ""
		if len(cve.Published) >= 10 {
			pub = cve.Published[:10]
		}

		results = append(results, Result{
			ID:          cve.ID,
			Description: desc,
			Score:       score,
			Severity:    severity,
			Published:   pub,
			URL:         "https://nvd.nist.gov/vuln/detail/" + cve.ID,
		})
	}

	// Sort by CVSS score descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	if len(results) > maxResults {
		results = results[:maxResults]
	}
	return results, nil
}

// extractCVSS returns the best available CVSS score and severity label.
func extractCVSS(
	v31 []struct {
		Type     string `json:"type"`
		CvssData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	},
	v30 []struct {
		Type     string `json:"type"`
		CvssData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	},
	v2 []struct {
		Type     string `json:"type"`
		CvssData struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"cvssData"`
	},
) (float64, string) {
	// Try v3.1 Primary first, then any v3.1
	for _, m := range v31 {
		if m.Type == "Primary" {
			return m.CvssData.BaseScore, m.CvssData.BaseSeverity
		}
	}
	if len(v31) > 0 {
		return v31[0].CvssData.BaseScore, v31[0].CvssData.BaseSeverity
	}
	// Try v3.0
	for _, m := range v30 {
		if m.Type == "Primary" {
			return m.CvssData.BaseScore, m.CvssData.BaseSeverity
		}
	}
	if len(v30) > 0 {
		return v30[0].CvssData.BaseScore, v30[0].CvssData.BaseSeverity
	}
	// Fall back to v2 (no severity string available in v2)
	if len(v2) > 0 {
		score := v2[0].CvssData.BaseScore
		return score, cvssV2Severity(score)
	}
	return 0, ""
}

// cvssV2Severity converts a CVSS v2 base score to a severity label.
func cvssV2Severity(score float64) string {
	switch {
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
