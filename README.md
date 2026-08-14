# ElevatedCLI

> Generate, scan, verify, and safely test AI-generated code from the terminal.

[![Go Version](https://img.shields.io/badge/go-1.22%2B-blue.svg)](https://golang.org)
[![Security Scale](https://img.shields.io/badge/security-0--100-green.svg)](#security-scoring)

`elevated-cli` ElevatedCLI is a Go-based command-line tool designed to make AI-assisted software development safer. It helps developers generate code through supported LLM providers, inspect that code for security risks, enforce organization policies, audit dependencies, and—when configured—execute code in an isolated environment.

---

The goal is simple:

```text
Generate code faster.
Verify code before trusting it.
Never execute untrusted code directly on the host.
```

> ⚠️ **Security notice:** AI-generated code is untrusted input. Static analysis and security scores reduce risk but do not guarantee that code is safe. Do not execute generated code on your local machine, CI runner, or production environment without verified sandbox isolation and restrictive execution controls.

---

## Features

### Current / Core Features

- Go-based CLI with a clean, extensible architecture
- AI provider abstraction for cloud and local LLMs
- Prompt-to-code generation workflow
- Generated-code extraction and syntax validation
- Static security analysis
- Custom security-policy enforcement
- Dependency vulnerability auditing
- Security scoring and verdict generation
- Human-readable terminal reports
- JSON output for CI/CD integration
- Structured logs and optional SQLite audit history
- Configurable security rules
- Cross-platform Go binary distribution

### Planned Security Capabilities

- `gosec` integration for Go security scanning
- `govulncheck` and OSV-Scanner dependency auditing
- AST-based rules using `go/ast` and `go/parser`
- Detection of hardcoded secrets and unsafe APIs
- Dangerous import and command-execution detection
- File-system and network-access policies
- Firecracker microVM execution support
- gVisor-based sandbox support
- CPU, memory, process, timeout, and output limits
- Network-deny-by-default sandbox policies
- SARIF report generation
- CI/CD security gates
- Software Bill of Materials (SBOM) generation

> Features listed as **planned** must not be treated as available until they are implemented, tested, and documented in the release notes.

---

## Why Secure AI Developer CLI?

AI coding tools can accelerate development, but generated code can contain:

- Hardcoded credentials and API keys
- SQL injection and command-injection risks
- Unsafe package imports
- Vulnerable third-party dependencies
- Insecure deserialization
- Excessive file-system permissions
- Unrestricted network access
- Unsafe shell or process execution
- Logic errors that static analysis may not detect

Secure AI Developer CLI places verification between AI generation and code execution:

```text
Developer Prompt
      │
      ▼
AI Code Generation
      │
      ▼
Code Extraction and Syntax Validation
      │
      ▼
Static Analysis and Custom AST Rules
      │
      ▼
Dependency Vulnerability Audit
      │
      ▼
Policy Enforcement
      │
      ▼
Sandboxed Execution
      │
      ▼
Security Score and Final Verdict
      │
      ▼
CLI Report and Audit Log
```

---

## Architecture

```text
secure-ai-cli/
├── cmd/
│   └── secure-ai-cli/
│       └── main.go
│
├── internal/
│   ├── ai/
│   │   ├── client.go
│   │   └── prompt_engineer.go
│   │
│   ├── config/
│   │   └── config.go
│   │
│   ├── verification/
│   │   ├── analyzer.go
│   │   ├── static_analyzer.go
│   │   ├── dependency_auditor.go
│   │   └── policy_engine.go
│   │
│   ├── sandbox/
│   │   ├── firecracker_runner.go
│   │   ├── process_runner.go
│   │   └── resource_governor.go
│   │
│   ├── output/
│   │   ├── reporter.go
│   │   └── ui.go
│   │
│   ├── logger/
│   │   └── logger.go
│   │
│   ├── database/
│   │   └── sqlite.go
│   │
│   └── util/
│       └── fs.go
│
├── pkg/
│   └── security/
│       └── types.go
│
├── test/
├── go.mod
├── go.sum
├── README.md
└── LICENSE
```

---

## Prerequisites

### Required

- Go 1.22 or later
- Git

### Optional Security Tools

Install these tools if the corresponding integration is enabled:

```bash
# Go static security analysis
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Go vulnerability scanning
go install golang.org/x/vuln/cmd/govulncheck@latest

# Multi-language dependency vulnerability scanning
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

### Optional Sandbox Runtime

For strong isolation, configure one of the following:

- [Firecracker](https://firecracker-microvm.github.io/)
- [gVisor](https://gvisor.dev/)

> Do not assume `os/exec`, Docker, or a simple subprocess is a secure sandbox. A local process runner may be useful for development, but it is not a production-grade boundary for hostile or untrusted code.

---

## Installation

### Build from Source

```bash
git clone https://github.com/your-org/secure-ai-cli.git
cd secure-ai-cli

go mod download
go build -o bin/secure-ai-cli ./cmd/secure-ai-cli
```

Verify the installation:

```bash
./bin/secure-ai-cli --help
```

### Install with Go

```bash
go install github.com/your-org/secure-ai-cli/cmd/secure-ai-cli@latest
```

---

## Quick Start

### 1. Configure an AI Provider

Create a configuration file:

```bash
mkdir -p ~/.config/secure-ai-cli
touch ~/.config/secure-ai-cli/config.yaml
```

Example configuration:

```yaml
provider:
  type: openai
  model: your-model-name
  timeout_seconds: 60

security:
  fail_closed: true
  minimum_score: 80
  allow_network: false
  allow_host_execution: false

analysis:
  gosec: true
  govulncheck: true
  osv_scanner: true
  custom_ast_rules: true

sandbox:
  enabled: true
  runtime: firecracker
  timeout_seconds: 20
  cpu_limit: 1
  memory_limit_mb: 512
  process_limit: 32
  output_limit_kb: 256
  network_mode: deny

audit:
  enabled: true
  database_path: ~/.local/share/secure-ai-cli/audit.db
  redact_prompts: true
  redact_secrets: true
```

Set your API key through the environment:

```bash
export OPENAI_API_KEY="your-api-key"
```

> Never commit API keys, tokens, credentials, or local configuration files containing secrets.

### 2. Generate Code

```bash
secure-ai-cli generate \
  --prompt "Create a Go HTTP API with a health endpoint" \
  --language go
```

### 3. Scan Existing Code

```bash
secure-ai-cli scan ./example-project
```

### 4. Verify Generated Code

```bash
secure-ai-cli verify \
  --file ./generated/main.go \
  --language go
```

### 5. Run in a Configured Sandbox

```bash
secure-ai-cli run \
  --file ./generated/main.go \
  --sandbox firecracker
```

> The `run` command should fail closed when no approved sandbox runtime is configured. Never silently fall back to direct host execution.

---

## Commands

| Command | Description |
|---|---|
| `generate` | Request code from a configured AI provider |
| `scan` | Analyze an existing project or file |
| `verify` | Run the full verification pipeline without execution |
| `run` | Verify and execute code in an approved sandbox |
| `policy` | Inspect, validate, or manage security policies |
| `report` | View or export prior verification results |
| `config` | View, validate, or initialize configuration |
| `doctor` | Check required tools, configuration, and sandbox readiness |

Example help command:

```bash
secure-ai-cli --help
secure-ai-cli verify --help
secure-ai-cli doctor
```

---

## Verification Pipeline

The CLI is designed to evaluate code through several stages.

### 1. Syntax Validation

Before security scanning, the tool should:

- Detect the generated language
- Extract code from structured AI output
- Validate syntax
- Reject malformed or incomplete code
- Prevent further execution if parsing fails

### 2. Static Security Analysis

For Go code, the tool can integrate with `gosec` and custom AST rules.

Typical findings may include:

- Hardcoded secrets
- Unsafe command execution
- Weak cryptography
- SQL-injection patterns
- Unsafe file permissions
- Path-traversal risks
- Insecure random-number usage
- Dangerous package imports
- Unsafe deserialization

### 3. Dependency Audit

The dependency auditor can inspect files such as:

```text
go.mod
package.json
package-lock.json
requirements.txt
pyproject.toml
Cargo.toml
```

It can use:

- `govulncheck` for Go modules
- OSV-Scanner for multi-language dependency auditing

### 4. Policy Enforcement

Policies allow teams to enforce project-specific security constraints.

Example policy rules:

```yaml
policies:
  - id: no-shell-exec
    severity: critical
    action: block
    description: Block direct shell or system command execution.

  - id: no-hardcoded-secrets
    severity: high
    action: block
    description: Prevent hardcoded API keys, passwords, and tokens.

  - id: no-unrestricted-network
    severity: high
    action: block
    description: Require explicit network allowlists.

  - id: restricted-imports
    severity: medium
    action: warn
    blocked_imports:
      - os/exec
      - syscall
      - unsafe
```

### 5. Isolated Execution

When sandboxing is enabled, generated code should run in an isolated, disposable environment with:

- A temporary workspace
- Restricted filesystem access
- Dropped privileges
- CPU and memory limits
- Process limits
- Timeout enforcement
- Output-size limits
- Network deny-by-default configuration
- Restricted environment variables
- Automatic cleanup after execution

---

## Security Score

The CLI can produce a score between `0` and `100`.

Example interpretation:

| Score | Verdict | Meaning |
|---:|---|---|
| 90–100 | `SAFE_WITH_REVIEW` | No critical findings; manual review is still recommended |
| 70–89 | `WARNING` | Risks or incomplete checks require developer attention |
| 40–69 | `HIGH_RISK` | Important security concerns were found |
| 0–39 | `BLOCKED` | Critical issues or unsafe execution conditions |
| N/A | `ANALYSIS_INCOMPLETE` | Required security checks could not complete |

A score must never override a critical policy violation, failed sandbox setup, or incomplete mandatory analysis. In those cases, the final status should be `BLOCKED` or `ANALYSIS_INCOMPLETE`.

Example output:

```text
Secure AI Developer CLI — Verification Report

Target: generated/main.go
Language: Go
Analysis ID: 8b7b9a2f

Static analysis:      2 findings
Dependency audit:     0 findings
Policy violations:    1 critical
Sandbox execution:    blocked
Security score:       32 / 100
Final verdict:        BLOCKED

Critical finding:
  [POLICY-001] Shell execution is not allowed
  File: generated/main.go:42
  Rule: no-shell-exec
  Recommendation: Remove os/exec usage or request explicit policy approval.
```

---

## JSON Output

Use JSON output for automation and CI/CD pipelines:

```bash
secure-ai-cli verify \
  --file ./generated/main.go \
  --output json
```

Example response:

```json
{
  "analysis_id": "8b7b9a2f",
  "target": "./generated/main.go",
  "language": "go",
  "score": 32,
  "verdict": "BLOCKED",
  "analysis_complete": true,
  "findings": [
    {
      "id": "POLICY-001",
      "severity": "CRITICAL",
      "category": "policy",
      "file": "generated/main.go",
      "line": 42,
      "message": "Shell execution is not allowed.",
      "remediation": "Remove os/exec usage or request policy approval."
    }
  ],
  "sandbox": {
    "attempted": false,
    "reason": "Blocked by critical policy violation."
  }
}
```

---

## CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: Secure AI Code Verification

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  secure-ai-scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.22.x"

      - name: Install Secure AI CLI
        run: go install github.com/your-org/secure-ai-cli/cmd/secure-ai-cli@latest

      - name: Verify generated code
        run: |
          secure-ai-cli scan . \
            --output json \
            --fail-on medium
```

Recommended CI behavior:

- Fail builds for critical findings
- Fail builds if mandatory analysis is incomplete
- Fail builds if policy enforcement is unavailable
- Do not allow host execution in shared CI runners
- Store JSON or SARIF reports as build artifacts
- Upload SARIF reports to supported security dashboards

---

## Configuration

Configuration can be supplied through:

1. Command-line flags
2. Environment variables
3. Configuration file
4. Secure secret manager integration

Priority order:

```text
CLI Flags > Environment Variables > Config File > Defaults
```

Example environment variables:

```bash
export SECURE_AI_PROVIDER_TYPE="openai"
export SECURE_AI_PROVIDER_MODEL="your-model-name"
export SECURE_AI_FAIL_CLOSED="true"
export SECURE_AI_SANDBOX_RUNTIME="firecracker"
export SECURE_AI_SANDBOX_NETWORK_MODE="deny"
```

---

## Threat Model

This tool treats the following as untrusted:

- AI-generated source code
- AI model output
- User prompts
- Third-party dependencies
- External scanner output
- Configuration supplied by untrusted environments
- Files within scanned projects unless explicitly trusted

The tool aims to reduce risk from:

- Arbitrary code execution
- Command injection
- Path traversal
- Secret leakage
- Unsafe dependency usage
- Data exfiltration
- Resource exhaustion
- Network abuse
- Policy bypasses
- False-positive “safe” decisions

### Out of Scope

This project does not guarantee that code is secure. It cannot fully protect against:

- Unknown vulnerabilities
- Flaws in third-party scanners
- Compromised host operating systems
- Compromised sandbox runtimes
- Malicious or compromised AI providers
- Logic bugs not detectable by the configured checks
- Social engineering or unsafe human approval decisions

---

## Security Principles

Secure AI Developer CLI follows these principles:

- **Fail closed:** If a required security control fails, block execution.
- **Least privilege:** Sandboxed workloads receive minimal privileges.
- **Deny by default:** Network access and dangerous operations require explicit approval.
- **Defense in depth:** Use multiple layers—syntax checks, SAST, dependency scanning, policies, and sandboxing.
- **No direct host execution:** Untrusted code must not run directly on the developer machine or CI host.
- **Auditability:** Record decisions, findings, and execution metadata.
- **Secret protection:** Redact secrets from logs and reports.
- **Deterministic policy decisions:** Policies must provide explainable results.

---

## Development

### Run Tests

```bash
go test ./...
```

### Run Static Checks

```bash
go vet ./...
gofmt -l .
```

### Run Go Security Analysis

```bash
gosec ./...
govulncheck ./...
```

### Build

```bash
go build ./cmd/secure-ai-cli
```

### Run Locally

```bash
go run ./cmd/secure-ai-cli --help
```

---

## Testing Requirements

Before considering a release ready, the project should include tests for:

- Malformed AI responses
- Invalid JSON and Markdown code extraction
- Unsupported language handling
- Syntax failures
- Hardcoded-secret detection
- Dangerous-import detection
- Command-execution detection
- SQL-injection detection
- Dependency vulnerability reporting
- Policy fail-closed behavior
- Safe command argument construction
- Path traversal protection
- Temporary-file cleanup
- Timeout handling
- CPU and memory limit behavior
- Output-size limit behavior
- Network denial behavior
- Sandbox cleanup
- Environment and secret isolation
- Security-score calculation
- Audit-log secret redaction
- CLI exit codes
- End-to-end verification flow

---

## Exit Codes

| Exit Code | Meaning |
|---:|---|
| `0` | Verification completed and no blocking findings were detected |
| `1` | Blocking security finding or policy violation |
| `2` | Invalid command usage or invalid input |
| `3` | Required analysis tool unavailable or analysis incomplete |
| `4` | Sandbox unavailable, failed, or unsafe configuration detected |
| `5` | Internal application error |

---

## Roadmap

### P0 — Required Before Untrusted Execution

- [ ] Enforce fail-closed verification behavior
- [ ] Prevent direct host execution
- [ ] Implement verified sandbox isolation
- [ ] Enforce timeout, memory, CPU, process, and output limits
- [ ] Deny network access by default
- [ ] Restrict filesystem and environment-variable access
- [ ] Add path traversal and temporary-file protections
- [ ] Ensure secrets never appear in logs or reports

### P1 — Secure MVP

- [ ] Cobra CLI commands and Viper configuration
- [ ] LLM provider abstraction
- [ ] Safe structured AI response parsing
- [ ] Go syntax validation
- [ ] `gosec` integration
- [ ] `govulncheck` and OSV-Scanner integration
- [ ] Configurable policy engine
- [ ] Deterministic security scoring
- [ ] Human-readable and JSON reports
- [ ] Structured logging
- [ ] SQLite audit storage
- [ ] Unit and integration tests

### P2 — Production Hardening

- [ ] Firecracker microVM support
- [ ] gVisor runtime support
- [ ] SARIF reporting
- [ ] SBOM generation
- [ ] Signed release binaries
- [ ] Reproducible builds
- [ ] CI security gates
- [ ] Policy bundles and versioning
- [ ] Audit retention controls
- [ ] Metrics and observability
- [ ] Multi-language analyzers
- [ ] Plugin architecture for analyzers

---

## Contributing

Contributions are welcome.

Before opening a pull request:

```bash
gofmt -w .
go vet ./...
go test ./...
```

Please ensure that:

- New security controls include tests.
- Security-sensitive changes include threat-model updates.
- No secrets are committed.
- New policies document their expected behavior.
- New external tools are pinned and validated.
- Changes do not weaken fail-closed behavior.
- Sandbox changes are reviewed carefully.

For major security changes, open an issue first to discuss architecture and threat-model impact.

---

## Responsible Disclosure

If you discover a security vulnerability, do not open a public issue.

Please report it privately to:

```text
security@your-domain.com
```

Include:

- A description of the issue
- Affected version or commit
- Reproduction steps
- Potential impact
- Suggested remediation, if available

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Disclaimer

Secure AI Developer CLI is a security-assistance tool, not a guarantee of secure software. Automated analysis can miss vulnerabilities, produce false positives, and depend on the reliability of external tools and sandbox runtimes.

Always use code review, testing, dependency controls, least-privilege deployment, and appropriate security practices before deploying AI-generated code.