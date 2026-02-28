// Package llm implements OWASP LLM Top 10 2025 security probes against LLM API endpoints.
// Supports OpenAI-compatible, Anthropic, Ollama, HuggingFace TGI, and generic REST APIs.
package llm

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/onoz1169/1scan/internal/scanner"
	"github.com/onoz1169/1scan/internal/scanner/llm/payloads"
)

// LLMScanner implements scanner.Scanner for LLM endpoint security testing.
type LLMScanner struct {
	authOpts scanner.AuthOptions
}

func New() *LLMScanner {
	return &LLMScanner{}
}

// NewWithAuth creates an LLMScanner that injects auth credentials into every request.
func NewWithAuth(opts scanner.AuthOptions) *LLMScanner {
	return &LLMScanner{authOpts: opts}
}

var embeddedPayloads map[string]payloads.PayloadFile

func init() {
	var err error
	embeddedPayloads, err = payloads.Load()
	if err != nil {
		// Non-fatal: embedded payloads missing, use hardcoded probes only
		embeddedPayloads = make(map[string]payloads.PayloadFile)
	}
}

func (s *LLMScanner) Name() string {
	return "llm"
}

func (s *LLMScanner) Scan(target string, timeoutSec int) (*scanner.LayerResult, error) {
	start := time.Now()
	result := &scanner.LayerResult{
		Layer:  "llm",
		Target: target,
	}

	client := &http.Client{
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Transport: scanner.NewAuthTransport(nil, s.authOpts),
	}

	target = strings.TrimRight(target, "/")

	// Step 1: Probe if target is an LLM API endpoint
	endpointType, modelName, err := detectLLMEndpoint(client, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("endpoint detection error: %v", err))
	}

	if endpointType == endpointNone {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "LLM00-001",
			Layer:       "llm",
			Title:       "LLM Endpoint Not Detected",
			Description: "The target does not appear to be an LLM API endpoint.",
			Severity:    scanner.SeverityInfo,
			Reference:   "OWASP LLM Top 10 2025",
			Evidence:    "No LLM-compatible response detected at standard endpoints.",
			Remediation: "To scan an LLM endpoint, provide a URL serving an OpenAI-compatible API (e.g., http://host:port) or an Ollama API.",
		})
		result.Duration = time.Since(start)
		return result, nil
	}

	// Step 2: Run probes against the detected LLM endpoint
	sendFunc := senderForEndpoint(client, target, endpointType, modelName)

	runPromptInjection(sendFunc, result)
	runSystemPromptLeakage(sendFunc, result)
	runSensitiveDisclosure(sendFunc, result)
	runImproperOutputHandling(sendFunc, result)
	runExcessiveAgency(sendFunc, result)
	runOverreliance(sendFunc, result)
	runRateLimiting(client, target, endpointType, modelName, result)
	runRAGPoisoning(sendFunc, result)

	result.Duration = time.Since(start)
	return result, nil
}
