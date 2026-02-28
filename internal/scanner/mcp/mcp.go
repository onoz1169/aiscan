// Package mcp implements MCP (Model Context Protocol) server security probes.
// Detects tool poisoning, dangerous capability exposure, and injection vulnerabilities
// per OWASP LLM Top 10 2025 (LLM08 Supply Chain, LLM09 Misinformation).
package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/onoz1169/1scan/internal/scanner"
)

// MCPScanner implements scanner.Scanner for MCP server security testing.
type MCPScanner struct {
	authOpts scanner.AuthOptions
}

func New() *MCPScanner {
	return &MCPScanner{}
}

func NewWithAuth(opts scanner.AuthOptions) *MCPScanner {
	return &MCPScanner{authOpts: opts}
}

func (s *MCPScanner) Name() string {
	return "mcp"
}

func (s *MCPScanner) Scan(target string, timeoutSec int) (*scanner.LayerResult, error) {
	start := time.Now()
	result := &scanner.LayerResult{
		Layer:  "mcp",
		Target: target,
	}

	client := &http.Client{
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Transport: scanner.NewAuthTransport(nil, s.authOpts),
	}

	target = strings.TrimRight(target, "/")

	// Step 1: Detect if target is an MCP server
	endpoint, serverInfo, err := detectMCPServer(client, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("MCP detection error: %v", err))
	}

	if endpoint == "" {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "MCP00-001",
			Layer:       "mcp",
			Title:       "MCP Server Not Detected",
			Description: "The target does not appear to be an MCP server.",
			Severity:    scanner.SeverityInfo,
			Reference:   "Model Context Protocol (MCP) — https://modelcontextprotocol.io",
			Evidence:    "No valid JSON-RPC initialize response detected.",
			Remediation: "To scan an MCP server, provide the MCP endpoint URL (e.g., http://host:port/mcp).",
		})
		result.Duration = time.Since(start)
		return result, nil
	}

	if serverInfo != "" {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "MCP00-002",
			Layer:       "mcp",
			Title:       "MCP Server Identified",
			Description: fmt.Sprintf("MCP server detected at %s", endpoint),
			Severity:    scanner.SeverityInfo,
			Reference:   "Model Context Protocol (MCP)",
			Evidence:    serverInfo,
			Remediation: "",
		})
	}

	// Step 2: List available tools
	tools, err := listTools(client, endpoint)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("tools/list error: %v", err))
		result.Duration = time.Since(start)
		return result, nil
	}

	if len(tools) == 0 {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "MCP00-003",
			Layer:       "mcp",
			Title:       "No Tools Exposed",
			Description: "MCP server responded but exposes no tools.",
			Severity:    scanner.SeverityInfo,
			Reference:   "Model Context Protocol (MCP)",
			Evidence:    "tools/list returned empty result",
			Remediation: "",
		})
		result.Duration = time.Since(start)
		return result, nil
	}

	// Step 3: Run probes
	runToolPoisoning(tools, result)
	runDangerousTools(client, endpoint, tools, result)
	runSSRFViaTools(client, endpoint, tools, result)

	result.Duration = time.Since(start)
	return result, nil
}

// --- JSON-RPC types ---

type jsonRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	ID      int         `json:"id"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *jsonRPCError   `json:"error"`
	ID      int             `json:"id"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCPTool represents an MCP tool definition.
type MCPTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// sendRPC sends a JSON-RPC request to the MCP endpoint.
func sendRPC(client *http.Client, endpoint string, req jsonRPCRequest) (*jsonRPCResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	// Handle SSE-wrapped response: "data: {...}\n\n"
	respStr := strings.TrimSpace(string(respBody))
	if strings.HasPrefix(respStr, "data:") {
		for _, line := range strings.Split(respStr, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "data:") {
				respStr = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				break
			}
		}
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal([]byte(respStr), &rpcResp); err != nil {
		return nil, fmt.Errorf("JSON parse: %w", err)
	}

	return &rpcResp, nil
}

// listTools calls tools/list and returns tool definitions.
func listTools(client *http.Client, endpoint string) ([]MCPTool, error) {
	resp, err := sendRPC(client, endpoint, jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/list",
		Params:  map[string]interface{}{},
		ID:      2,
	})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	var listResult struct {
		Tools []MCPTool `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &listResult); err != nil {
		return nil, fmt.Errorf("parse tools: %w", err)
	}

	return listResult.Tools, nil
}

// callTool calls a tool with the given arguments.
func callTool(client *http.Client, endpoint, toolName string, args map[string]interface{}) (string, error) {
	resp, err := sendRPC(client, endpoint, jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      toolName,
			"arguments": args,
		},
		ID: 3,
	})
	if err != nil {
		return "", err
	}
	if resp.Error != nil {
		return "", fmt.Errorf("RPC error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	return string(resp.Result), nil
}

// truncate shortens a string for display in findings.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
