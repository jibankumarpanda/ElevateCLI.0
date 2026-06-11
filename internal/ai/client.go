package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sashabaranov/go-openai"
)

// LLMClient defines the interface for interacting with different AI providers.
type LLMClient interface {
	GenerateCode(ctx context.Context, prompt string, lang string) (string, error)
	Provider() string
	Model() string
}

// OpenAIClient implements LLMClient for OpenAI.
type OpenAIClient struct {
	client *openai.Client
	model  string
}

func NewOpenAIClient(apiKey, model string) *OpenAIClient {
	return &OpenAIClient{
		client: openai.NewClient(apiKey),
		model:  model,
	}
}

func (c *OpenAIClient) GenerateCode(ctx context.Context, prompt string, lang string) (string, error) {
	resp, err := c.client.CreateChatCompletion(
		ctx,
		openai.ChatCompletionRequest{
			Model: c.model,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleSystem,
					Content: fmt.Sprintf("You are a secure-coding expert. Generate only the raw %s code with no explanations or markdown backticks.", lang),
				},
				{
					Role:    openai.ChatMessageRoleUser,
					Content: prompt,
				},
			},
		},
	)

	if err != nil {
		return "", fmt.Errorf("openai error: %w", err)
	}

	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("no response from openai")
	}

	return resp.Choices[0].Message.Content, nil
}

// OllamaClient implements LLMClient for local Ollama models.
type OllamaClient struct {
	endpoint string
	model    string
	client   *http.Client
}

func NewOllamaClient(endpoint, model string) *OllamaClient {
	return &OllamaClient{
		endpoint: endpoint,
		model:    model,
		client:   &http.Client{},
	}
}

func (c *OllamaClient) GenerateCode(ctx context.Context, prompt string, lang string) (string, error) {
	url := fmt.Sprintf("%s/api/generate", c.endpoint)

	payload := map[string]interface{}{
		"model":  c.model,
		"prompt": fmt.Sprintf("You are a secure-coding expert. Generate only the raw %s code for: %s", lang, prompt),
		"stream": false,
		"system": fmt.Sprintf("Generate only the raw %s code with no explanations or markdown backticks.", lang),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama returned status: %d", resp.StatusCode)
	}

	var result struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode ollama response: %w", err)
	}

	return result.Response, nil
}
