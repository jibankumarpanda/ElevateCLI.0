package ai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// ─── Prompt construction ──────────────────────────────────────────────────────

func TestBuildGeneratePrompt(t *testing.T) {
	p := BuildGeneratePrompt("write a REST handler", "python")
	if !strings.Contains(p, "python") || !strings.Contains(p, "write a REST handler") {
		t.Errorf("prompt missing language/request: %s", p)
	}
	p2 := BuildGeneratePrompt("hello", "")
	if !strings.Contains(p2, "go") {
		t.Errorf("empty language should default to go: %s", p2)
	}
}

func TestExtractCodeBlock(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		wantCode   string
		wantLang   string
	}{
		{
			name:     "go fence",
			raw:      "Here you go:\n```go\npackage main\n```\nDone.",
			wantCode: "package main",
			wantLang: "go",
		},
		{
			name:     "python alias",
			raw:      "```py\nprint(1)\n```",
			wantCode: "print(1)",
			wantLang: "python",
		},
		{
			name:     "js alias",
			raw:      "```js\nconsole.log(1)\n```",
			wantCode: "console.log(1)",
			wantLang: "javascript",
		},
		{
			name:     "no fence",
			raw:      "  just some text  ",
			wantCode: "just some text",
			wantLang: "",
		},
		{
			name:     "typescript alias",
			raw:      "```tsx\nconst x: number = 1\n```",
			wantCode: "const x: number = 1",
			wantLang: "typescript",
		},
		{
			name:     "golang alias",
			raw:      "```golang\nfmt.Println()\n```",
			wantCode: "fmt.Println()",
			wantLang: "go",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, lang := ExtractCodeBlock(c.raw)
			if code != c.wantCode {
				t.Errorf("code = %q, want %q", code, c.wantCode)
			}
			if lang != c.wantLang {
				t.Errorf("lang = %q, want %q", lang, c.wantLang)
			}
		})
	}
}

func TestConstructPrompt(t *testing.T) {
	pe := NewPromptEngineer("go")
	p := pe.ConstructPrompt("make a server", "python")
	if !strings.Contains(p, "python") || !strings.Contains(p, "make a server") {
		t.Errorf("ConstructPrompt output wrong: %s", p)
	}
	pDefault := pe.ConstructPrompt("make a server", "")
	if !strings.Contains(pDefault, "go") {
		t.Errorf("empty lang should use default: %s", pDefault)
	}
	if pe.DefaultLanguage != "go" {
		t.Errorf("DefaultLanguage = %q", pe.DefaultLanguage)
	}
}

// ─── Client construction ──────────────────────────────────────────────────────

func TestNewUnknownProvider(t *testing.T) {
	_, err := New(config.AIConfig{Provider: "wat"})
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
	var provErr *sec.AIProviderError
	if !asAIProviderError(err, &provErr) {
		t.Fatalf("expected AIProviderError, got %T: %v", err, err)
	}
	if provErr.Provider != "wat" {
		t.Errorf("provider = %q", provErr.Provider)
	}
}

func TestNewOpenAIMissingKey(t *testing.T) {
	_, err := New(config.AIConfig{Provider: "openai"})
	if err == nil {
		t.Fatal("expected error for missing API key")
	}
}

func TestNewOpenAIWithKey(t *testing.T) {
	c, err := New(config.AIConfig{Provider: "openai", APIKey: "sk-test", Model: "gpt-4o"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Provider() != "openai" || c.Model() != "gpt-4o" {
		t.Errorf("client = %s/%s", c.Provider(), c.Model())
	}
}

func TestNewOllama(t *testing.T) {
	c, err := New(config.AIConfig{Provider: "ollama", Model: "llama3", Endpoint: "http://localhost:11434/api/generate"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Provider() != "local" {
		t.Errorf("Provider() = %q, want local", c.Provider())
	}
}

// ─── Anthropic + Ollama Generate (mock HTTP) ─────────────────────────────────

func TestAnthropicGenerate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-api-key"); got != "sk-ant-test" {
			t.Errorf("x-api-key = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"content":[{"type":"text","text":"claude answer"}]}`))
	}))
	defer srv.Close()

	c := &anthropicClient{apiKey: "sk-ant-test", model: "claude-3", baseURL: srv.URL, http: srv.Client()}
	got, err := c.Generate(context.Background(), "hi")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if got != "claude answer" {
		t.Errorf("Generate = %q", got)
	}
}

func TestAnthropicGenerateHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	}))
	defer srv.Close()

	c := &anthropicClient{apiKey: "k", model: "m", baseURL: srv.URL, http: srv.Client()}
	if _, err := c.Generate(context.Background(), "hi"); err == nil {
		t.Error("expected error on non-200 response")
	}
}

func TestOllamaGenerate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"response":"ollama answer"}`))
	}))
	defer srv.Close()

	c := &ollamaClient{baseURL: srv.URL, model: "llama3", http: srv.Client()}
	got, err := c.Generate(context.Background(), "hi")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if got != "ollama answer" {
		t.Errorf("Generate = %q", got)
	}
}

func asAIProviderError(err error, target **sec.AIProviderError) bool {
	for err != nil {
		if pe, ok := err.(*sec.AIProviderError); ok {
			*target = pe
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
