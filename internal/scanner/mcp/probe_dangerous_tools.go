package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/onoz1169/1scan/internal/scanner"
)

// --- MCP02: Dangerous Tools Exposed Without Authentication ---
// Detects tools with dangerous capabilities (file system, shell, credentials)
// that are accessible without authentication.
//
// Reference: OWASP LLM Top 10 2025 - LLM06 (Excessive Agency)

type dangerousPattern struct {
	keywords    []string
	category    string
	description string
	severity    scanner.Severity
}

var dangerousPatterns = []dangerousPattern{
	{
		keywords:    []string{"exec", "execute", "run_command", "shell", "bash", "cmd", "powershell", "subprocess"},
		category:    "code-execution",
		description: "Tool may execute arbitrary OS commands.",
		severity:    scanner.SeverityCritical,
	},
	{
		keywords:    []string{"eval", "python_eval", "js_eval", "ruby_eval"},
		category:    "code-eval",
		description: "Tool may evaluate arbitrary code.",
		severity:    scanner.SeverityCritical,
	},
	{
		keywords:    []string{"write_file", "create_file", "save_file", "file_write", "overwrite"},
		category:    "file-write",
		description: "Tool may write or overwrite files on the server.",
		severity:    scanner.SeverityHigh,
	},
	{
		keywords:    []string{"read_file", "file_read", "open_file", "read_config", "cat_file"},
		category:    "file-read",
		description: "Tool may read arbitrary files from the server filesystem.",
		severity:    scanner.SeverityHigh,
	},
	{
		keywords:    []string{"delete_file", "remove_file", "unlink", "rmdir"},
		category:    "file-delete",
		description: "Tool may delete files on the server.",
		severity:    scanner.SeverityHigh,
	},
	{
		keywords:    []string{"get_secret", "read_secret", "get_password", "get_credentials", "get_api_key", "get_token", "get_env"},
		category:    "credential-access",
		description: "Tool may expose secrets, passwords, or API keys.",
		severity:    scanner.SeverityCritical,
	},
	{
		keywords:    []string{"database_query", "sql_query", "db_execute", "run_query", "execute_sql"},
		category:    "database-access",
		description: "Tool may execute arbitrary database queries.",
		severity:    scanner.SeverityHigh,
	},
}

func runDangerousTools(client *http.Client, endpoint string, tools []MCPTool, result *scanner.LayerResult) {
	for _, tool := range tools {
		checkDangerousTool(client, endpoint, tool, result)
	}
}

func checkDangerousTool(client *http.Client, endpoint string, tool MCPTool, result *scanner.LayerResult) {
	nameLower := strings.ToLower(tool.Name)
	descLower := strings.ToLower(tool.Description)

	for _, pattern := range dangerousPatterns {
		matched := false
		for _, kw := range pattern.keywords {
			if strings.Contains(nameLower, kw) || strings.Contains(descLower, kw) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		// Try invoking the tool without auth to check for unauthenticated access
		authRequired := checkAuthRequired(client, endpoint, tool)

		findingID := fmt.Sprintf("MCP02-%s", sanitizeID(tool.Name))
		sev := pattern.severity
		authNote := "Authentication requirement could not be verified."
		if !authRequired {
			// Tool executed without auth — escalate severity
			if sev == scanner.SeverityHigh {
				sev = scanner.SeverityCritical
			}
			authNote = "Tool responded WITHOUT authentication — unauthenticated access confirmed."
		}

		result.Findings = append(result.Findings, scanner.Finding{
			ID:    findingID,
			Layer: "mcp",
			Title: fmt.Sprintf("Dangerous Tool Exposed: '%s' (%s)", tool.Name, pattern.category),
			Description: fmt.Sprintf(
				"Tool '%s' exposes %s %s",
				tool.Name, pattern.description, authNote,
			),
			Severity:    sev,
			Reference:   "OWASP LLM Top 10 2025 - LLM06 (Excessive Agency)",
			Evidence:    truncate(fmt.Sprintf("name: %s\ndescription: %s", tool.Name, tool.Description), 600),
			Remediation: "Restrict dangerous tools with authentication and authorization. Apply least-privilege: only expose tools required by the use case. Use allowlists to restrict tool access per client identity.",
		})
		return // One finding per tool
	}
}

// checkAuthRequired tries to invoke the tool with minimal arguments and checks
// whether the server returns an auth error or actually executes the tool.
func checkAuthRequired(client *http.Client, endpoint string, tool MCPTool) bool {
	// Build minimal arguments from schema
	args := buildMinimalArgs(tool.InputSchema)

	result, err := callTool(client, endpoint, tool.Name, args)
	if err != nil {
		// RPC error often means auth required or invalid args — not unauthenticated exec
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "401") ||
			strings.Contains(errStr, "403") ||
			strings.Contains(errStr, "unauthorized") ||
			strings.Contains(errStr, "forbidden") ||
			strings.Contains(errStr, "authentication") {
			return true
		}
		return true // Assume auth required if error
	}

	// Tool responded — check if it's an auth error in the result body
	lower := strings.ToLower(result)
	if strings.Contains(lower, "unauthorized") ||
		strings.Contains(lower, "forbidden") ||
		strings.Contains(lower, "authentication required") ||
		strings.Contains(lower, "access denied") {
		return true
	}

	// Tool executed without auth error
	return false
}

// buildMinimalArgs constructs a minimal argument map from the tool's input schema.
func buildMinimalArgs(schema json.RawMessage) map[string]interface{} {
	args := map[string]interface{}{}
	if len(schema) == 0 {
		return args
	}

	var s struct {
		Properties map[string]struct {
			Type    string      `json:"type"`
			Default interface{} `json:"default"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(schema, &s); err != nil {
		return args
	}

	for _, req := range s.Required {
		prop, ok := s.Properties[req]
		if !ok {
			args[req] = ""
			continue
		}
		switch prop.Type {
		case "string":
			if prop.Default != nil {
				args[req] = prop.Default
			} else {
				args[req] = "test"
			}
		case "integer", "number":
			args[req] = 0
		case "boolean":
			args[req] = false
		default:
			args[req] = ""
		}
	}

	return args
}
