// Package virustotal provides a client for the VirusTotal API v3 (free tier).
// Requires a free API key: https://www.virustotal.com/gui/sign-in
// Free tier: 4 requests/minute, 500 requests/day.
// NOT for commercial use on free tier.
package virustotal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const vtBaseURL = "https://www.virustotal.com/api/v3"

// AnalysisStats is the breakdown of engine verdicts.
type AnalysisStats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Harmless   int `json:"harmless"`
	Undetected int `json:"undetected"`
}

// URLReport holds the key fields from a VirusTotal URL analysis.
type URLReport struct {
	URL        string
	Stats      AnalysisStats
	Reputation int
	Categories map[string]string
}

// IPReport holds the key fields from a VirusTotal IP analysis.
type IPReport struct {
	IP         string
	Stats      AnalysisStats
	Reputation int
	Country    string
	ASOwner    string
}

// vtAnalysisData is the shared analysis wrapper in VT API responses.
type vtAnalysisData struct {
	Attributes struct {
		LastAnalysisStats AnalysisStats     `json:"last_analysis_stats"`
		Reputation        int               `json:"reputation"`
		Categories        map[string]string `json:"categories"`
		Country           string            `json:"country"`
		AsOwner           string            `json:"as_owner"`
		Network           string            `json:"network"`
	} `json:"attributes"`
}

// Client is a VirusTotal API v3 client.
type Client struct {
	apiKey string
	http   *http.Client
	last   time.Time
}

// New creates a VirusTotal client with the given API key.
func New(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		http:   &http.Client{Timeout: 15 * time.Second},
	}
}

// rateLimit enforces VirusTotal's 4 req/min limit (15s between requests).
func (c *Client) rateLimit() {
	const delay = 15 * time.Second
	if elapsed := time.Since(c.last); elapsed < delay {
		time.Sleep(delay - elapsed)
	}
	c.last = time.Now()
}

func (c *Client) get(path string) (*vtAnalysisData, error) {
	c.rateLimit()

	req, err := http.NewRequest("GET", vtBaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("virustotal request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("virustotal: rate limited (429); try again in 60s")
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("virustotal: invalid API key")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // URL/IP not in VT database yet
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("virustotal: HTTP %d", resp.StatusCode)
	}

	var wrapper struct {
		Data vtAnalysisData `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("decode virustotal response: %w", err)
	}
	return &wrapper.Data, nil
}

// CheckURL checks a URL's reputation in VirusTotal.
func (c *Client) CheckURL(rawURL string) (*URLReport, error) {
	// VT URL ID = base64url(url) without padding
	id := strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(rawURL)), "=")
	data, err := c.get("/urls/" + id)
	if err != nil || data == nil {
		return nil, err
	}
	return &URLReport{
		URL:        rawURL,
		Stats:      data.Attributes.LastAnalysisStats,
		Reputation: data.Attributes.Reputation,
		Categories: data.Attributes.Categories,
	}, nil
}

// CheckIP checks an IP address's reputation in VirusTotal.
func (c *Client) CheckIP(ip string) (*IPReport, error) {
	data, err := c.get("/ip_addresses/" + ip)
	if err != nil || data == nil {
		return nil, err
	}
	return &IPReport{
		IP:         ip,
		Stats:      data.Attributes.LastAnalysisStats,
		Reputation: data.Attributes.Reputation,
		Country:    data.Attributes.Country,
		ASOwner:    data.Attributes.AsOwner,
	}, nil
}
