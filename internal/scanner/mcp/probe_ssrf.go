package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/onoz1169/1scan/internal/scanner"
)

// --- MCP03: SSRF via Tool URL Parameters ---
// Detects tools that accept URL parameters and may be abused for Server-Side
// Request Forgery (SSRF) to access internal services or cloud metadata endpoints.
//
// Reference: OWASP Top 10 2021 - A10 (SSRF) / OWASP LLM Top 10 2025 - LLM02

// ssrfProbes are payloads targeting common internal endpoints.
var ssrfProbes = []struct {
	url      string
	category string
}{
	{"http://169.254.169.254/latest/meta-data/", "AWS IMDS"},
	{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS"},
	{"http://metadata.google.internal/computeMetadata/v1/", "GCP Metadata"},
	{"http://localhost/", "localhost"},
	{"http://127.0.0.1/", "loopback"},
	{"http://[::1]/", "IPv6 loopback"},
	{"http://0.0.0.0/", "all-interfaces"},
	{"http://10.0.0.1/", "private-network-10"},
	{"http://192.168.1.1/", "private-network-192"},
	{"http://172.16.0.1/", "private-network-172"},
}

// urlParamIndicators are parameter names/descriptions suggesting URL input.
var urlParamIndicators = []string{
	"url", "uri", "endpoint", "link", "href", "location",
	"fetch", "download", "request_url", "target_url",
	"source", "src", "redirect",
}

func runSSRFViaTools(client *http.Client, endpoint string, tools []MCPTool, result *scanner.LayerResult) {
	for _, tool := range tools {
		checkSSRFTool(client, endpoint, tool, result)
	}
}

func checkSSRFTool(client *http.Client, endpoint string, tool MCPTool, result *scanner.LayerResult) {
	// Find URL-accepting parameters
	urlParams := findURLParams(tool.InputSchema)
	if len(urlParams) == 0 {
		// Also check tool name/description for fetch-like tools
		nameLower := strings.ToLower(tool.Name + " " + tool.Description)
		for _, ind := range urlParamIndicators {
			if strings.Contains(nameLower, ind) {
				// No typed schema but looks like a URL tool — report as medium
				result.Findings = append(result.Findings, scanner.Finding{
					ID:    fmt.Sprintf("MCP03-%s-SCHEMA", sanitizeID(tool.Name)),
					Layer: "mcp",
					Title: fmt.Sprintf("Potential SSRF Surface: '%s' (no input schema)", tool.Name),
					Description: fmt.Sprintf(
						"Tool '%s' appears to accept URLs based on its name/description but has no validated input schema. "+
							"If it processes arbitrary URLs, it may be vulnerable to SSRF.",
						tool.Name,
					),
					Severity:    scanner.SeverityMedium,
					Reference:   "OWASP Top 10 2021 - A10:SSRF / OWASP LLM Top 10 2025 - LLM02",
					Evidence:    truncate(fmt.Sprintf("name: %s\ndescription: %s", tool.Name, tool.Description), 400),
					Remediation: "Validate and allowlist URLs accepted by fetch-type tools. Block requests to private IP ranges and cloud metadata endpoints.",
				})
				return
			}
		}
		return
	}

	// Try SSRF probes using the first URL parameter
	paramName := urlParams[0]
	for _, probe := range ssrfProbes {
		args := map[string]interface{}{paramName: probe.url}
		resp, err := callTool(client, endpoint, tool.Name, args)
		if err != nil {
			continue
		}

		lower := strings.ToLower(resp)

		// Skip if server explicitly blocked the request (false-positive guard)
		blockedIndicators := []string{
			"not allowed", "blocked", "forbidden", "access denied",
			"allowlist", "whitelist", "invalid url", "url not permitted",
		}
		blocked := false
		for _, b := range blockedIndicators {
			if strings.Contains(lower, b) {
				blocked = true
				break
			}
		}
		if blocked {
			continue
		}

		// Check for actual internal resource content in the response
		ssrfIndicators := []string{
			"instance-id", "ami-id", "local-ipv4", "availability-zone", // AWS IMDS
			"\"compute\"", "project-id", "service-account",             // GCP metadata
			"subscriptionid", "vmid", "resourcegroupname",              // Azure IMDS
			"root:x:", "www-data:", "daemon:",                          // /etc/passwd
			"<title>", "server: nginx", "server: apache",              // Internal HTTP server
		}

		for _, ind := range ssrfIndicators {
			if strings.Contains(lower, ind) {
				result.Findings = append(result.Findings, scanner.Finding{
					ID:    fmt.Sprintf("MCP03-%s", sanitizeID(tool.Name)),
					Layer: "mcp",
					Title: fmt.Sprintf("SSRF Confirmed via Tool '%s' → %s", tool.Name, probe.category),
					Description: fmt.Sprintf(
						"Tool '%s' (parameter: %s) successfully fetched internal resource %s. "+
							"Indicator found in response: '%s'.",
						tool.Name, paramName, probe.url, ind,
					),
					Severity:    scanner.SeverityCritical,
					Reference:   "OWASP Top 10 2021 - A10:SSRF",
					Evidence:    truncate(resp, 500),
					Remediation: "Implement URL allowlisting. Block requests to 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16. Validate URL scheme (only https://).",
				})
				return
			}
		}
	}
}

// findURLParams returns parameter names from the input schema that likely accept URLs.
func findURLParams(schema json.RawMessage) []string {
	if len(schema) == 0 {
		return nil
	}

	var s struct {
		Properties map[string]struct {
			Type        string `json:"type"`
			Description string `json:"description"`
			Format      string `json:"format"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schema, &s); err != nil {
		return nil
	}

	var result []string
	for name, prop := range s.Properties {
		nameLower := strings.ToLower(name)
		descLower := strings.ToLower(prop.Description)

		if prop.Format == "uri" || prop.Format == "url" {
			result = append(result, name)
			continue
		}

		for _, ind := range urlParamIndicators {
			if strings.Contains(nameLower, ind) || strings.Contains(descLower, ind+" ") {
				result = append(result, name)
				break
			}
		}
	}
	return result
}
