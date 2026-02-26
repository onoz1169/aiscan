package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/onoz1169/1scan/internal/scanner"
)

// --- Probe: LLM10 Unbounded Consumption ---

// rateLimitResult holds the outcome of a single rapid-fire request.
type rateLimitResult struct {
	status int
	err    error
	dur    time.Duration
}

// runRateLimiting tests for LLM10 (Unbounded Consumption) by sending rapid-fire
// and large-context requests and checking whether the endpoint applies rate limiting.
func runRateLimiting(client *http.Client, target string, kind endpointKind, model string, result *scanner.LayerResult) {
	// --- Sub-probe 1: Rapid-fire requests (burst of 10 concurrent) ---
	const burstSize = 10
	results := make([]rateLimitResult, burstSize)
	var wg sync.WaitGroup

	for i := 0; i < burstSize; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			start := time.Now()
			status, err := sendRaw(client, target, kind, model, "Say OK.")
			results[idx] = rateLimitResult{status: status, err: err, dur: time.Since(start)}
		}(i)
	}
	wg.Wait()

	successCount := 0
	rateLimited := 0
	var totalDuration time.Duration
	for _, r := range results {
		if r.err != nil {
			continue
		}
		totalDuration += r.dur
		if r.status == http.StatusOK {
			successCount++
		}
		if r.status == http.StatusTooManyRequests {
			rateLimited++
		}
	}

	if successCount == burstSize && rateLimited == 0 {
		avgMs := int64(0)
		if successCount > 0 {
			avgMs = totalDuration.Milliseconds() / int64(successCount)
		}
		result.Findings = append(result.Findings, scanner.Finding{
			ID:    "LLM10-001",
			Layer: "llm",
			Title: "No Rate Limiting Detected on LLM Endpoint",
			Description: fmt.Sprintf(
				"Sent %d concurrent requests; all returned HTTP 200 with no throttling (avg %dms). "+
					"The endpoint does not appear to enforce rate limits, making it vulnerable to resource exhaustion and denial-of-wallet attacks.",
				burstSize, avgMs),
			Severity:    scanner.SeverityHigh,
			Reference:   "OWASP LLM Top 10 2025 - LLM10",
			Evidence:    fmt.Sprintf("%d/%d requests succeeded (HTTP 200), 0 rate-limited (HTTP 429)", successCount, burstSize),
			Remediation: "Implement rate limiting per API key/IP (e.g., token bucket). Set max requests per minute and max tokens per request. Use API gateway throttling.",
		})
	}

	// --- Sub-probe 2: Large context payload ---
	largePrompt := strings.Repeat("Repeat this word: test. ", 2000) // ~50K chars
	start := time.Now()
	status, err := sendRaw(client, target, kind, model, largePrompt)
	largeDur := time.Since(start)

	if err == nil && status == http.StatusOK {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:    "LLM10-002",
			Layer: "llm",
			Title: "Large Context Request Accepted Without Restriction",
			Description: fmt.Sprintf(
				"A ~50KB prompt was accepted and processed (HTTP 200 in %dms). "+
					"The endpoint does not appear to enforce input size limits, risking resource exhaustion.",
				largeDur.Milliseconds()),
			Severity:    scanner.SeverityMedium,
			Reference:   "OWASP LLM Top 10 2025 - LLM10",
			Evidence:    fmt.Sprintf("~50KB prompt accepted, HTTP %d, response in %dms", status, largeDur.Milliseconds()),
			Remediation: "Enforce maximum input token/character limits. Reject or truncate oversized prompts before they reach the model. Set per-request compute budgets.",
		})
	}
}

// sendRaw sends a prompt to the LLM endpoint and returns the HTTP status code.
// Unlike sendPrompt, this exposes the status code for rate-limit detection.
func sendRaw(client *http.Client, target string, kind endpointKind, model string, prompt string) (int, error) {
	var url string
	var body interface{}

	switch kind {
	case endpointOpenAI:
		if model == "" {
			model = "gpt-3.5-turbo"
		}
		url = target + "/v1/chat/completions"
		body = map[string]interface{}{
			"model":    model,
			"messages": []map[string]string{{"role": "user", "content": prompt}},
		}
	case endpointAnthropic:
		url = target + "/v1/messages"
		body = map[string]interface{}{
			"model":      "claude-3-haiku-20240307",
			"messages":   []map[string]string{{"role": "user", "content": prompt}},
			"max_tokens": 100,
		}
	case endpointOllama:
		if model == "" {
			model = "llama3.2"
		}
		url = target + "/api/chat"
		body = map[string]interface{}{
			"model":    model,
			"messages": []map[string]string{{"role": "user", "content": prompt}},
			"stream":   false,
		}
	case endpointHFTGI:
		url = target + "/generate"
		body = map[string]interface{}{
			"inputs":     prompt,
			"parameters": map[string]interface{}{"max_new_tokens": 50},
		}
	default:
		url = target + "/"
		body = map[string]interface{}{"prompt": prompt}
	}

	jsonBytes, err := json.Marshal(body)
	if err != nil {
		return 0, fmt.Errorf("marshal error: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBytes))
	if err != nil {
		return 0, fmt.Errorf("request error: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	return resp.StatusCode, nil
}
