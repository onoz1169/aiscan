// Package abuseipdb provides a client for the AbuseIPDB API v2 (free tier).
// Requires a free API key: https://www.abuseipdb.com/register
// Free tier: 1,000 checks/day.
package abuseipdb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const abuseIPDBURL = "https://api.abuseipdb.com/api/v2/check"

// CheckResult holds the AbuseIPDB response for an IP check.
type CheckResult struct {
	IP                  string
	AbuseConfidenceScore int   // 0-100
	TotalReports        int
	NumDistinctUsers    int
	LastReportedAt      string
	CountryCode         string
	ISP                 string
	UsageType           string
}

// abuseIPDBResponse mirrors the API response.
type abuseIPDBResponse struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		TotalReports         int    `json:"totalReports"`
		NumDistinctUsers     int    `json:"numDistinctUsers"`
		LastReportedAt       string `json:"lastReportedAt"`
		CountryCode          string `json:"countryCode"`
		Isp                  string `json:"isp"`
		UsageType            string `json:"usageType"`
	} `json:"data"`
}

// Client is an AbuseIPDB API client.
type Client struct {
	apiKey string
	http   *http.Client
}

// New creates an AbuseIPDB client with the given API key.
func New(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		http:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Check looks up abuse reports for the given IP address.
// maxAgeDays controls how old reports to include (max 365, recommended 90).
func (c *Client) Check(ip string, maxAgeDays int) (*CheckResult, error) {
	if maxAgeDays <= 0 || maxAgeDays > 365 {
		maxAgeDays = 90
	}

	params := url.Values{}
	params.Set("ipAddress", ip)
	params.Set("maxAgeInDays", fmt.Sprintf("%d", maxAgeDays))
	params.Set("verbose", "false")

	req, err := http.NewRequest("GET", abuseIPDBURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("abuseipdb request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("abuseipdb: rate limited (429)")
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("abuseipdb: invalid API key")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("abuseipdb: HTTP %d", resp.StatusCode)
	}

	var apiResp abuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decode abuseipdb response: %w", err)
	}

	d := apiResp.Data
	return &CheckResult{
		IP:                   d.IPAddress,
		AbuseConfidenceScore: d.AbuseConfidenceScore,
		TotalReports:         d.TotalReports,
		NumDistinctUsers:     d.NumDistinctUsers,
		LastReportedAt:       d.LastReportedAt,
		CountryCode:          d.CountryCode,
		ISP:                  d.Isp,
		UsageType:            d.UsageType,
	}, nil
}
