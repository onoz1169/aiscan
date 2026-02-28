package mcp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/onoz1169/1scan/internal/scanner"
)

// --- MCP01: Tool Poisoning ---
// Detects injected instructions in tool names, descriptions, and schema metadata.
// Adversaries poison tool definitions to hijack LLM behavior when the tool manifest
// is consumed by an AI agent.
//
// Reference: OWASP LLM Top 10 2025 - LLM09 (Misinformation) / LLM08 (Supply Chain)
// See also: CVE-2025-XXXX series (MCP tool poisoning)

// injectionKeywords are patterns that suggest instruction injection in a tool definition.
var injectionKeywords = []struct {
	pattern  string
	category string
}{
	// Instruction override
	{"ignore all previous", "instruction-override"},
	{"ignore previous instructions", "instruction-override"},
	{"disregard your", "instruction-override"},
	{"forget your instructions", "instruction-override"},
	{"override your", "instruction-override"},
	{"bypass your", "instruction-override"},
	{"your new task is", "instruction-override"},
	{"new directive:", "instruction-override"},
	{"system update:", "instruction-override"},

	// Authority claims
	{"you must always", "authority-claim"},
	{"you are required to", "authority-claim"},
	{"as an admin", "authority-claim"},
	{"as a developer", "authority-claim"},
	{"trusted tool", "authority-claim"},
	{"this is an internal", "authority-claim"},

	// Exfiltration patterns
	{"send to http", "exfiltration"},
	{"post to http", "exfiltration"},
	{"forward to", "exfiltration"},
	{"exfiltrate", "exfiltration"},
	{"call this url", "exfiltration"},
	{"make a request to", "exfiltration"},

	// Hidden content markers
	{"[hidden:", "hidden-instruction"},
	{"<!-- ", "hidden-instruction"},
	{"<hidden>", "hidden-instruction"},
	{"/*hidden*/", "hidden-instruction"},
	{"[system:", "hidden-instruction"},
	{"<system>", "hidden-instruction"},
	{"[instruction:", "hidden-instruction"},
}

// suspiciousToolNames are tool names that suggest dangerous capabilities.
var suspiciousToolNamePatterns = []struct {
	keyword  string
	category string
}{
	{"eval", "code-execution"},
	{"exec", "code-execution"},
	{"run_command", "code-execution"},
	{"shell", "code-execution"},
	{"bash", "code-execution"},
	{"cmd", "code-execution"},
	{"powershell", "code-execution"},
	{"subprocess", "code-execution"},
	{"system(", "code-execution"},

	{"read_file", "filesystem"},
	{"write_file", "filesystem"},
	{"delete_file", "filesystem"},
	{"list_directory", "filesystem"},
	{"file_access", "filesystem"},

	{"get_secret", "credential-access"},
	{"read_secret", "credential-access"},
	{"get_password", "credential-access"},
	{"get_token", "credential-access"},
	{"get_api_key", "credential-access"},
}

func runToolPoisoning(tools []MCPTool, result *scanner.LayerResult) {
	for _, tool := range tools {
		checkToolForPoisoning(tool, result)
	}
}

func checkToolForPoisoning(tool MCPTool, result *scanner.LayerResult) {
	combined := strings.ToLower(tool.Name + " " + tool.Description)

	// Check schema descriptions and defaults
	schemaText := extractSchemaText(tool.InputSchema)
	combined += " " + strings.ToLower(schemaText)

	var matches []string
	var category string
	for _, kw := range injectionKeywords {
		if strings.Contains(combined, kw.pattern) {
			matches = append(matches, fmt.Sprintf("'%s' (%s)", kw.pattern, kw.category))
			if category == "" {
				category = kw.category
			}
		}
	}

	if len(matches) == 0 {
		return
	}

	sev := scanner.SeverityHigh
	if category == "exfiltration" || category == "instruction-override" {
		sev = scanner.SeverityCritical
	}

	result.Findings = append(result.Findings, scanner.Finding{
		ID:          fmt.Sprintf("MCP01-%s", sanitizeID(tool.Name)),
		Layer:       "mcp",
		Title:       fmt.Sprintf("Tool Poisoning Detected in '%s'", tool.Name),
		Description: fmt.Sprintf("Tool '%s' contains patterns associated with prompt injection or instruction hijacking. Patterns found: %s. When an LLM agent consumes this tool manifest, these instructions may override the LLM's intended behavior.", tool.Name, strings.Join(matches, ", ")),
		Severity:    sev,
		Reference:   "OWASP LLM Top 10 2025 - LLM09 / MCP Tool Poisoning",
		Evidence:    truncate(fmt.Sprintf("name: %s\ndescription: %s", tool.Name, tool.Description), 800),
		Remediation: "Audit all tool definitions for injected instructions. Never trust tool descriptions from external/unverified MCP servers. Implement tool manifest signing and verification.",
	})
}

// extractSchemaText extracts text content from an inputSchema for analysis.
func extractSchemaText(schema json.RawMessage) string {
	if len(schema) == 0 {
		return ""
	}

	var s map[string]interface{}
	if err := json.Unmarshal(schema, &s); err != nil {
		return string(schema)
	}

	var collect func(v interface{}) string
	collect = func(v interface{}) string {
		switch val := v.(type) {
		case string:
			return val
		case map[string]interface{}:
			var parts []string
			for _, mv := range val {
				parts = append(parts, collect(mv))
			}
			return strings.Join(parts, " ")
		case []interface{}:
			var parts []string
			for _, item := range val {
				parts = append(parts, collect(item))
			}
			return strings.Join(parts, " ")
		}
		return ""
	}

	return collect(s)
}

func sanitizeID(name string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(name) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	s := b.String()
	if len(s) > 20 {
		return s[:20]
	}
	return s
}
