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

//Factory

// New returns the correct Client implementation based on config.
func New(cfg config.AIConfig) (Client, error) {
	switch cfg.Provider {
	case "openai":
		return newOpenAIClient(cfg)
	case "anthropic":
		return newAnthropicClient(cfg)
	case "local":
		return newOllamaClient(cfg)
	default:
		return nil, &sec.AIProviderError{
			Provider: cfg.Provider,
			Message:  "unknown provider — must be openai, anthropic, or local",
		}
	}
}

// OpenAIClient implements LLMClient for OpenAI.
type openAIClient struct {
	client *openai.Client
	model  string
}

func newOpenAIClient(cfg config.AIConfig) (*openAIClient, error) {
	if cfg.APIKey == "" {
		return nil, &sec.AIProviderError{
			Provider: "openai",
			Message:  "api_key is empty — set OPENAI_API_KEY environment variable",
		}
	}
	return &openAIClient{
		client: openai.NewClient(cfg.APIKey),
		model:  cfg.Model,
	}, nil
}

func (c *openAIClient) Generate(ctx context.Context, prompt string) (string, error) {
	log := logger.WithStage("ai-openai")
	log.Info("calling OpenAI API")

	resp, err := c.client.CreateChatCompletion(ctx,
		openai.ChatCompletionRequest{
			Model: c.model,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleSystem,
					Content: systemPrompt(),
				},
				{
					Role:    openai.ChatMessageRoleUser,
					Content: prompt,
				},
			},
		},
	)
	if err != nil {
		return "", &sec.AIProviderError{Provider: "openai", Message: "API call failed", Err: err}
	}
	if len(resp.Choices) == 0 {
		return "", &sec.AIProviderError{Provider: "openai", Message: "empty response from API"}
	}
	return resp.Choices[0].Message.Content, nil
}
//Anthropic (Claude)
type anthropicClient struct {
	apiKey  string
	model   string
	baseURL string
	http    *http.Client
}

func newAnthropicClient(cfg config.AIConfig) (*anthropicClient, error) {
	if cfg.APIKey == "" {
		return nil, &sec.AIProviderError{
			Provider: "anthropic",
			Message:  "api_key is empty — set ANTHROPIC_API_KEY environment variable",
		}
	}
	return &anthropicClient{
		apiKey:  cfg.APIKey,
		model:   cfg.Model,
		baseURL: "https://api.anthropic.com/v1/messages",
		http:    &http.Client{Timeout: time.Duration(cfg.TimeoutSec) * time.Second},
	}, nil
}

func (c *anthropicClient) Generate(ctx context.Context, prompt string) (string, error) {
	log := logger.WithStage("ai-anthropic")
	log.Info("calling Anthropic API")

	body := map[string]any{
		"model":      c.model,
		"max_tokens": 4096,
		"system":     systemPrompt(),
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	b, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", &sec.AIProviderError{Provider: "anthropic", Message: "HTTP request failed", Err: err}
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", &sec.AIProviderError{
			Provider: "anthropic",
			Message:  fmt.Sprintf("API returned %d: %s", resp.StatusCode, string(rawBody)),
		}
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(rawBody, &result); err != nil {
		return "", fmt.Errorf("parsing response: %w", err)
	}
	if len(result.Content) == 0 {
		return "", &sec.AIProviderError{Provider: "anthropic", Message: "empty content in response"}
	}
	return result.Content[0].Text, nil
}

func (c *anthropicClient) Provider() string { return "anthropic" }
func (c *anthropicClient) Model() string    { return c.model }

// OllamaClient implements LLMClient for local Ollama models.
type ollamaClient struct {
	baseURL string
	model   string
	http    *http.Client
}

func newOllamaClient(cfg config.AIConfig) (*ollamaClient, error) {
	url := cfg.LocalURL
	if url == "" {
		url = "http://localhost:11434/api/generate"
	}
	return &ollamaClient{
		baseURL: url,
		model:   cfg.Model,
		http:    &http.Client{Timeout: time.Duration(cfg.TimeoutSec) * time.Second},
	}, nil
}

func (c *ollamaClient) Generate(ctx context.Context, prompt string) (string, error) {
	log := logger.WithStage("ai-ollama")
	log.Info("calling local Ollama API")

	body := map[string]any{
		"model":  c.model,
		"prompt": systemPrompt() + "\n\n" + prompt,
		"stream": false,
	}

	b, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", &sec.AIProviderError{Provider: "local", Message: "Ollama unreachable", Err: err}
	}
	defer resp.Body.Close()

	var result struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("parsing Ollama response: %w", err)
	}
	return result.Response, nil
}

func (c *ollamaClient) Provider() string { return "local" }
func (c *ollamaClient) Model() string    { return c.model }

// ─── System prompt ────────────────────────────────────────────────────────────

// systemPrompt returns the instruction every LLM receives before the user prompt.
// It ensures code is returned in a parseable format.
func systemPrompt() string {
	return `You are a senior software engineer. When asked to write code:
1. Return ONLY the code inside a single markdown code block (` + "```" + `language ... ` + "```" + `).
2. Do NOT include explanations, commentary, or multiple code blocks.
3. Write clean, idiomatic code with proper error handling.
4. Never include hardcoded credentials, API keys, or passwords.
5. Prefer standard library functions over third-party dependencies where possible.`
}
