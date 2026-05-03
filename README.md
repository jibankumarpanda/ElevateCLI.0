# Secure AI Developer CLI (secure-ai)

A production-grade, security-first CLI tool for AI code generation.

## Features
- AI-generated code via OpenAI or Ollama.
- 4-stage security verification pipeline (SAST, Dependencies, Policy, Sandbox).
- Weighted security scoring (0-100).
- Audit logging to SQLite.

## Phase 1 Implementation
- CLI scaffolding with Cobra.
- Configuration management with Viper.
- LLM integration (OpenAI, Ollama).
- Prompt engineering for secure coding.

## Setup
1. Install Go 1.22+.
2. Clone the repository.
3. Run `go mod tidy`.
4. Set your `OPENAI_API_KEY` environment variable or update `.secure-ai.yaml`.

## Usage
```bash
go run cmd/secure-ai-cli/main.go generate --prompt "Write a function to sum two numbers" --lang go
```
