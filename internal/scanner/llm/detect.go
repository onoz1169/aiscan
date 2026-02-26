package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// sendPrompt is a function that sends a prompt and returns the text response.
type sendPrompt func(prompt string) (string, error)

// --- Endpoint types and detection ---

type endpointKind int

const (
	endpointNone endpointKind = iota
	endpointOpenAI
	endpointOllama
	endpointAnthropic
	endpointHFTGI
	endpointGeneric
)

func detectLLMEndpoint(client *http.Client, target string) (endpointKind, string, error) {
	// Try to auto-detect model name first
	modelName := autoDetectModel(client, target)

	// Try OpenAI-compatible
	if resp, err := tryOpenAI(client, target, "Hello", modelName); err == nil {
		if looksLikeLLMResponse(resp) {
			return endpointOpenAI, modelName, nil
		}
	}

	// Try Anthropic-compatible
	if resp, err := tryAnthropic(client, target, "Hello"); err == nil {
		if looksLikeLLMResponse(resp) {
			return endpointAnthropic, "", nil
		}
	}

	// Try Ollama-compatible
	if resp, err := tryOllama(client, target, "Hello", modelName); err == nil {
		if looksLikeLLMResponse(resp) {
			return endpointOllama, modelName, nil
		}
	}

	// Try Hugging Face TGI
	if resp, err := tryHFTGI(client, target, "Hello"); err == nil {
		if looksLikeLLMResponse(resp) {
			return endpointHFTGI, "", nil
		}
	}

	// Try generic POST
	if resp, err := tryGeneric(client, target, "Hello"); err == nil {
		if looksLikeLLMResponse(resp) {
			return endpointGeneric, "", nil
		}
	}

	return endpointNone, "", nil
}

// autoDetectModel tries to discover available models from listing endpoints.
func autoDetectModel(client *http.Client, target string) string {
	// Try OpenAI /v1/models
	if name := tryModelList(client, target+"/v1/models"); name != "" {
		return name
	}
	// Try Ollama /api/tags
	if name := tryOllamaTags(client, target+"/api/tags"); name != "" {
		return name
	}
	return ""
}

func tryModelList(client *http.Client, url string) string {
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ""
	}

	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err == nil && len(result.Data) > 0 {
		return result.Data[0].ID
	}
	return ""
}

func tryOllamaTags(client *http.Client, url string) string {
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ""
	}

	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &result); err == nil && len(result.Models) > 0 {
		return result.Models[0].Name
	}
	return ""
}

func tryOpenAI(client *http.Client, target, prompt, model string) (string, error) {
	if model == "" {
		model = "gpt-3.5-turbo"
	}
	body := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	return postJSON(client, target+"/v1/chat/completions", body)
}

func tryAnthropic(client *http.Client, target, prompt string) (string, error) {
	body := map[string]interface{}{
		"model": "claude-3-haiku-20240307",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"max_tokens": 100,
	}
	return postJSON(client, target+"/v1/messages", body)
}

func tryOllama(client *http.Client, target, prompt, model string) (string, error) {
	if model == "" {
		model = "llama3.2"
	}
	body := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"stream": false,
	}
	return postJSON(client, target+"/api/chat", body)
}

func tryHFTGI(client *http.Client, target, prompt string) (string, error) {
	body := map[string]interface{}{
		"inputs": prompt,
		"parameters": map[string]interface{}{
			"max_new_tokens": 50,
		},
	}
	return postJSON(client, target+"/generate", body)
}

func tryGeneric(client *http.Client, target, prompt string) (string, error) {
	body := map[string]interface{}{
		"prompt": prompt,
	}
	return postJSON(client, target+"/", body)
}

func postJSON(client *http.Client, url string, body interface{}) (string, error) {
	jsonBytes, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal error: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBytes))
	if err != nil {
		return "", fmt.Errorf("request error: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non-200 status: %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return "", fmt.Errorf("read error: %w", err)
	}

	return string(respBody), nil
}

func looksLikeLLMResponse(body string) bool {
	lower := strings.ToLower(body)
	markers := []string{"choices", "message", "content", "response", "generated_text"}
	for _, m := range markers {
		if strings.Contains(lower, fmt.Sprintf(`"%s"`, m)) {
			return true
		}
	}
	return false
}

func senderForEndpoint(client *http.Client, target string, kind endpointKind, model string) sendPrompt {
	return func(prompt string) (string, error) {
		switch kind {
		case endpointOpenAI:
			return tryOpenAI(client, target, prompt, model)
		case endpointAnthropic:
			return tryAnthropic(client, target, prompt)
		case endpointOllama:
			return tryOllama(client, target, prompt, model)
		case endpointHFTGI:
			return tryHFTGI(client, target, prompt)
		default:
			return tryGeneric(client, target, prompt)
		}
	}
}
