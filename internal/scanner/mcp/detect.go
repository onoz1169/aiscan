package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// detectMCPServer tries to find an MCP endpoint at the given target.
// Returns (endpoint URL, server info string, error).
func detectMCPServer(client *http.Client, target string) (string, string, error) {
	// Try common MCP endpoint paths
	candidates := []string{
		target,
		target + "/mcp",
		target + "/sse",
		target + "/api/mcp",
		target + "/v1/mcp",
	}

	for _, candidate := range candidates {
		serverInfo, err := tryInitialize(client, candidate)
		if err == nil {
			return candidate, serverInfo, nil
		}
	}

	return "", "", fmt.Errorf("no MCP endpoint found")
}

// tryInitialize sends an MCP initialize request and returns server info on success.
func tryInitialize(client *http.Client, endpoint string) (string, error) {
	resp, err := sendRPC(client, endpoint, jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    "1scan",
				"version": "0.1.4",
			},
		},
		ID: 1,
	})
	if err != nil {
		return "", err
	}
	if resp.Error != nil {
		return "", fmt.Errorf("initialize error: %s", resp.Error.Message)
	}

	// Parse server info
	var initResult struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
		Capabilities json.RawMessage `json:"capabilities"`
	}
	if err := json.Unmarshal(resp.Result, &initResult); err != nil {
		// Response parsed but not valid MCP initialize result
		return "", fmt.Errorf("invalid initialize response")
	}

	// Must have protocolVersion to be a valid MCP server
	if !strings.HasPrefix(initResult.ProtocolVersion, "2024-") &&
		!strings.HasPrefix(initResult.ProtocolVersion, "2025-") {
		return "", fmt.Errorf("unknown protocol version: %s", initResult.ProtocolVersion)
	}

	info := fmt.Sprintf("MCP %s", initResult.ProtocolVersion)
	if initResult.ServerInfo.Name != "" {
		info += fmt.Sprintf(" — %s", initResult.ServerInfo.Name)
		if initResult.ServerInfo.Version != "" {
			info += fmt.Sprintf(" v%s", initResult.ServerInfo.Version)
		}
	}

	return info, nil
}
