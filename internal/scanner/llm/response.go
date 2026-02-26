package llm

import "encoding/json"

// extractTextContent parses a raw LLM API response body and returns the text content.
// Supports OpenAI, Anthropic, Ollama, HuggingFace TGI, and generic formats.
func extractTextContent(raw string) string {
	// Try OpenAI format: .choices[0].message.content
	var openAIResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(raw), &openAIResp); err == nil {
		if len(openAIResp.Choices) > 0 && openAIResp.Choices[0].Message.Content != "" {
			return openAIResp.Choices[0].Message.Content
		}
	}

	// Try Anthropic format: .content[0].text
	var anthropicResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal([]byte(raw), &anthropicResp); err == nil {
		if len(anthropicResp.Content) > 0 && anthropicResp.Content[0].Text != "" {
			return anthropicResp.Content[0].Text
		}
	}

	// Try Ollama format: .response or .message.content
	var ollamaResp struct {
		Response string `json:"response"`
		Message  struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.Unmarshal([]byte(raw), &ollamaResp); err == nil {
		if ollamaResp.Response != "" {
			return ollamaResp.Response
		}
		if ollamaResp.Message.Content != "" {
			return ollamaResp.Message.Content
		}
	}

	// Try HF TGI format: [0].generated_text or .generated_text
	var hfArrayResp []struct {
		GeneratedText string `json:"generated_text"`
	}
	if err := json.Unmarshal([]byte(raw), &hfArrayResp); err == nil {
		if len(hfArrayResp) > 0 && hfArrayResp[0].GeneratedText != "" {
			return hfArrayResp[0].GeneratedText
		}
	}

	var hfResp struct {
		GeneratedText string `json:"generated_text"`
	}
	if err := json.Unmarshal([]byte(raw), &hfResp); err == nil {
		if hfResp.GeneratedText != "" {
			return hfResp.GeneratedText
		}
	}

	// Fallback: return raw
	return raw
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
