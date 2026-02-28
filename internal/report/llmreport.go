package report

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

const defaultModel = "claude-sonnet-4-6"
const anthropicAPIURL = "https://api.anthropic.com/v1/messages"
const anthropicVersion = "2023-06-01"

// LLMReportConfig holds configuration for LLM-enhanced report generation.
type LLMReportConfig struct {
	APIKey  string        // Anthropic API key
	Model   string        // Model ID (default: claude-sonnet-4-6)
	Lang    Lang          // Output language (default: en)
	Timeout time.Duration // HTTP timeout (default: 60s)
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

// GenerateLLMReport calls the Anthropic API to produce an enhanced executive report
// from the scan result. Returns the LLM-generated text.
func GenerateLLMReport(result *scanner.ScanResult, cfg LLMReportConfig) (string, error) {
	if cfg.Model == "" {
		cfg.Model = defaultModel
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}

	prompt := buildLLMPrompt(result, cfg.Lang)

	reqBody, err := json.Marshal(anthropicRequest{
		Model:     cfg.Model,
		MaxTokens: 1500,
		Messages: []anthropicMessage{
			{Role: "user", Content: prompt},
		},
	})
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, anthropicAPIURL, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", cfg.APIKey)
	req.Header.Set("anthropic-version", anthropicVersion)

	client := &http.Client{Timeout: cfg.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp anthropicResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if apiResp.Error != nil {
		return "", fmt.Errorf("API error (%s): %s", apiResp.Error.Type, apiResp.Error.Message)
	}
	if len(apiResp.Content) == 0 {
		return "", fmt.Errorf("empty response from API")
	}

	return apiResp.Content[0].Text, nil
}

// buildLLMPrompt constructs the prompt sent to the LLM.
func buildLLMPrompt(result *scanner.ScanResult, lang Lang) string {
	var sb strings.Builder
	counts := result.TotalFindings()

	sb.WriteString("You are a senior security analyst. Analyze the following 1scan security scan results.\n\n")
	sb.WriteString(fmt.Sprintf("Target: %s\n", result.Target))
	sb.WriteString(fmt.Sprintf("Scan duration: %s\n", formatDuration(result.EndTime.Sub(result.StartTime))))
	sb.WriteString(fmt.Sprintf("Findings: CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d INFO=%d\n\n",
		counts[scanner.SeverityCritical], counts[scanner.SeverityHigh],
		counts[scanner.SeverityMedium], counts[scanner.SeverityLow], counts[scanner.SeverityInfo]))

	if len(result.AttackChains) > 0 {
		sb.WriteString("Detected attack chains:\n")
		for _, c := range result.AttackChains {
			sb.WriteString(fmt.Sprintf("  [%s] %s\n    → %s\n", c.Severity, c.Title, c.Description))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("Findings (excluding INFO):\n")
	for _, lr := range result.Layers {
		for _, f := range lr.Findings {
			if f.Severity == scanner.SeverityInfo {
				continue
			}
			sb.WriteString(fmt.Sprintf("\n[%s][%s] %s\n", strings.ToUpper(f.Layer), f.Severity, f.Title))
			if f.Evidence != "" {
				sb.WriteString(fmt.Sprintf("  Evidence: %s\n", f.Evidence))
			}
			if f.Remediation != "" {
				sb.WriteString(fmt.Sprintf("  Fix: %s\n", f.Remediation))
			}
		}
	}

	sb.WriteString("\n---\n")
	if lang == LangJA {
		sb.WriteString("以下の内容を日本語で回答してください:\n")
	}
	sb.WriteString("\nProvide the following in a clear, structured format:\n")
	sb.WriteString("1. **Executive Summary** (2-3 sentences covering overall risk level and most critical issues)\n")
	sb.WriteString("2. **Top 3 Prioritized Actions** (specific, actionable steps ordered by impact)\n")
	sb.WriteString("3. **Risk Assessment** (overall risk level: Critical/High/Medium/Low, and business impact if unaddressed)\n")
	if len(result.AttackChains) > 0 {
		sb.WriteString("4. **Attack Chain Analysis** (explain the attack chains and why they are dangerous together)\n")
	}

	return sb.String()
}
