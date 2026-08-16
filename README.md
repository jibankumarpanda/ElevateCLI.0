# ElevatedCLI

> Generate, verify, and safely test AI-generated code from the terminal.

[![Go Version](https://img.shields.io/badge/go-1.25-blue.svg)](https://golang.org)
[![Security Scale](https://img.shields.io/badge/security-0--100-green.svg)](#security-scoring)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`elevated-cli` is a Go-based CLI that generates code through supported LLM providers, then runs every result through a **4-stage security pipeline** (static analysis → dependency audit → policy enforcement → sandboxed execution) before showing you a verdict and a deterministic **security score (0–100)**.

```text
Generate code faster.
Verify code before trusting it.
Never execute untrusted code directly on the host.
```

> ⚠️ **Security notice:** AI-generated code is untrusted input. Static analysis and security scores reduce risk but do not guarantee that code is safe. Do not execute generated code on your local machine, CI runner, or production environment without verified sandbox isolation and restrictive execution controls.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Verification Pipeline](#verification-pipeline)
- [Security Scoring](#security-scoring)
- [Output Formats](#output-formats)
- [Configuration](#configuration)
- [Security Policies](#security-policies)
- [Audit History](#audit-history)
- [Exit Codes](#exit-codes)
- [Threat Model](#threat-model)
- [Security Principles](#security-principles)
- [Architecture](#architecture)
- [Development](#development)
- [Testing Requirements](#testing-requirements)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Responsible Disclosure](#responsible-disclosure)
- [License](#license)

---

## Features

### Implemented

- Go-based CLI (`elevated-cli`) with Cobra commands and Viper configuration
- AI provider abstraction: **OpenAI**, **Anthropic**, and **local/Ollama** endpoints
- Prompt-to-code generation with markdown code-block extraction
- **4-stage security pipeline** (see [below](#verification-pipeline)):
  1. Static analysis — `gosec` (Go) plus custom `go/ast` and pattern-based checks
  2. Dependency audit — `govulncheck` (Go) and `osv-scanner` (multi-language lockfiles)
  3. Policy enforcement — configurable blocked imports/functions and error-handling rules
  4. Sandboxed execution — isolated process runner with timeout and environment scrubbing
- Deterministic security scoring (0–100) with fail-closed verdicts
- Report formats: **rich** (terminal), **json**, **sarif**, **plain**
- Structured logging (console or JSON) via `zap`
- SQLite audit history (`history` command)
- `audit` command for existing files/directories, including CVE scanning of lockfiles
- `config` command to inspect or modify configuration
- GitHub Actions CI/CD integration via JSON/SARIF output

### Planned (not yet implemented)

- Firecracker microVM and gVisor isolation (the process runner is the current default)
- Docker-based sandbox isolation
- Memory, CPU, and network enforcement inside the process runner (config exists; limits are not yet applied at the syscall level)
- SBOM generation
- Signed release binaries and reproducible builds
- CI security gates (exit-code contract only today)
- Policy bundles and versioning
- Audit retention controls
- Metrics and observability

> Features listed as **planned** must not be treated as available until they are implemented, tested, and documented in the release notes.

---

## How It Works

AI coding tools can accelerate development, but generated code can contain:

- Hardcoded credentials and API keys
- SQL injection and command-injection risks
- Unsafe package imports
- Vulnerable third-party dependencies
- Insecure deserialization
- Unsafe shell or process execution
- Logic errors that static analysis may not detect

ElevatedCLI places verification between AI generation and any use of the code:

```text
Developer Prompt
      │
      ▼
AI Code Generation (OpenAI / Anthropic / Ollama)
      │
      ▼
Code Extraction and Syntax Validation
      │
      ▼
Stage 1 — Static Analysis (gosec + AST + patterns)
      │
      ▼
Stage 2 — Dependency Audit (govulncheck / osv-scanner)
      │
      ▼
Stage 3 — Policy Enforcement (blocked imports/functions)
      │
      ▼
Stage 4 — Sandboxed Execution (isolated process)
      │
      ▼
Security Score (0–100) and Verdict
      │
      ▼
CLI Report and Audit Log (SQLite)
```

---

## Installation

### Build from Source

```bash
git clone https://github.com/jibankumarpanda/ElevateCLI.git
cd ElevateCLI

go build -o bin/elevated-cli ./cmd/elevated-cli
```

Verify the installation:

```bash
./bin/elevated-cli --help
```

### Install with Go

```bash
go install github.com/jibankumarpanda/ElevateCLI.0/cmd/elevated-cli@latest
```

### Prerequisites

- **Go 1.25 or later** (the module declares `go 1.25.0`)
- Git

### Optional Security Tools

The pipeline calls these tools when their integration is enabled (all on by default). If a required binary is missing, the pipeline **fails closed** with an `ANALYSIS_INCOMPLETE` verdict rather than reporting a clean scan.

```bash
# Go static security analysis (Stage 1)
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Go vulnerability scanning (Stage 2)
go install golang.org/x/vuln/cmd/govulncheck@latest

# Multi-language dependency vulnerability scanning (Stage 2)
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

### Optional Sandbox Runtimes

- For strong isolation, [Firecracker](https://firecracker-microvm.github.io/) and [gVisor](https://gvisor.dev/) are on the roadmap. Today the default is the built-in **process runner**.
- The process runner uses restricted `os/exec`: strict timeout, temp-directory isolation, scrubbed environment, and process-group teardown. It is **not** a production-grade boundary for hostile code — do not treat it as a substitute for a real sandbox.

---

## Quick Start

### 1. Configure an AI Provider

Create a config file (default search path: `.elevated-cli.yaml` in the current or home directory):

```bash
touch .elevated-cli.yaml
```

Example configuration:

```yaml
ai:
  provider: openai        # openai | anthropic | local
  model: gpt-4o
  api_key: ""             # or set via SECURE_AI_AI_API_KEY / OPENAI_API_KEY
  endpoint: http://localhost:11434   # used by local/Ollama
  timeout_sec: 120

sandbox:
  mode: process           # process | firecracker | docker | skip
  timeout_sec: 10
  max_memory_mb: 256
  block_network: true

output:
  format: rich            # rich | json | sarif | plain
  show_code: false
  audit_db: secure-ai.db  # SQLite path for scan history

scoring:
  sast_weight: 0.40
  dep_weight: 0.30
  policy_weight: 0.20
  sandbox_weight: 0.10
  pass_threshold: 70
  fail_closed: true

analysis:
  govulncheck: true
  osv_scanner: true
  custom_ast_rules: true

policy:
  file: .elevated-cli.yaml
  rules:
    blocked_imports:
      - os/exec
      - syscall
      - unsafe
      - net/http
    blocked_functions:
      - eval
      - exec
      - system
    require_error_handling: true
```

Set your API key through the environment:

```bash
export SECURE_AI_AI_API_KEY="your-api-key"
```

> Never commit API keys, tokens, credentials, or local configuration files containing secrets.

### 2. Generate Code

```bash
elevated-cli generate \
  --prompt "Create a Go HTTP API with a health endpoint" \
  --lang go
```

### 3. Run Generated Code in the Sandbox

```bash
elevated-cli generate \
  --prompt "read a CSV and print row count" \
  --lang python \
  --run
```

### 4. Audit an Existing File or Directory

```bash
# Single file
elevated-cli audit --file ./mycode.go

# Whole directory (recursive, skips vendor/node_modules/hidden dirs)
elevated-cli audit --dir ./src --lang python
```

### 5. Browse Past Scans

```bash
elevated-cli history --last 10
elevated-cli history --date 2025-04-24
elevated-cli history --id <scan-id>
```

---

## Commands

| Command | Description |
|---|---|
| `generate` | Generate code from an AI provider and run it through the security pipeline |
| `audit` | Run the security pipeline on an existing file or directory |
| `history` | Browse past scan results from the SQLite audit database |
| `config` | View or modify ElevatedCLI configuration |

### Global Flags

| Flag | Description |
|---|---|
| `--config <path>` | Explicit config file (default: `.elevated-cli.yaml` in home or current dir) |
| `--output <format>` | Output format: `rich` \| `json` \| `sarif` \| `plain` |
| `--no-sandbox` | Skip sandbox execution (faster, less safe) |
| `--verbose` | Enable debug logging |

### `generate`

```bash
elevated-cli generate --prompt "..." --lang go
```

| Flag | Description |
|---|---|
| `-p, --prompt` | Natural-language description of the code to generate (required) |
| `-l, --lang` | Target language: `go` \| `python` \| `javascript` \| `typescript` (default `go`) |
| `-m, --model` | LLM model override (e.g. `gpt-4o`, `claude-3-5-sonnet-20241022`) |
| `--sandbox` | Sandbox mode override: `firecracker` \| `process` \| `docker` |
| `--run` | Execute generated code in the sandbox after verification |
| `--dry-run` | Print the generated prompt without calling the LLM |
| `-o, --output` | Output format: `rich` \| `json` \| `sarif` \| `plain` |

### `audit`

```bash
elevated-cli audit --dir ./src
```

| Flag | Description |
|---|---|
| `-f, --file` | Path to a single file to audit |
| `-d, --dir` | Path to a directory to audit recursively |
| `-l, --lang` | Language override (auto-detected from extension if omitted) |
| `-o, --output` | Output format: `rich` \| `json` \| `sarif` \| `plain` |

### `history`

```bash
elevated-cli history --last 10
```

| Flag | Description |
|---|---|
| `-n, --last` | Number of recent scans to show (default 10) |
| `-d, --date` | Filter by date (`YYYY-MM-DD`) |
| `--id` | Show the full report for a specific scan ID |

### `config`

```bash
elevated-cli config --show
elevated-cli config --set ai.model=gpt-4o
```

| Flag | Description |
|---|---|
| `--show` | Print the current resolved configuration (default) |
| `--set` | Set a config value: `key=value` |

---

## Verification Pipeline

Every piece of code is evaluated through four stages. Stages 1–3 run in **parallel**; stage 4 (sandbox) runs after they complete.

### Stage 1 — Static Security Analysis (SAST)

- **Go**: custom `go/ast` checks (hardcoded-secret detection, dangerous calls such as `exec.Command`, `os.Remove(All)`, `net.Dial`, `http.Get`, `ioutil.ReadFile`) plus `gosec`. If the `gosec` binary is missing, the stage returns an error and the pipeline **fails closed**.
- **Python**: pattern checks for `eval(`, `exec(`, `os.system(`, `pickle.loads`, `subprocess.call(`, `shell=True`, hardcoded passwords.
- **JavaScript/TypeScript**: pattern checks for `eval(`, `innerHTML`, `document.write(`, `dangerouslySetInnerHTML`, `process.env`.
- **Other languages**: generic checks for hardcoded passwords/secrets and unresolved security TODOs.

Typical findings include:

- Hardcoded secrets
- Unsafe command execution
- SQL-injection patterns (`gosec` G201/G202)
- Unsafe file permissions (`gosec` G301/G302/G306)
- Path-traversal risks (`gosec` G304)
- Unhandled errors (`gosec` G104)
- Dangerous package imports

### Stage 2 — Dependency Audit

The dependency auditor extracts declared imports from the code and, when a project directory is available, scans lockfiles for known vulnerabilities.

Supported lockfiles:

```text
go.mod  go.sum
package-lock.json  npm-shrinkwrap.json  yarn.lock  pnpm-lock.yaml
requirements.txt  Pipfile.lock  poetry.lock  pyproject.toml
Cargo.lock  composer.lock  Gemfile.lock
```

- `go.sum` files are skipped when a `go.mod` exists in the same directory (govulncheck already covers the module).
- **govulncheck** scans Go modules; **osv-scanner** scans all lockfiles.
- An enabled scanner whose binary is missing is a hard, fail-closed error: a missing scanner must never be reported as a clean scan.
- When no lockfile exists (e.g. `generate` with no on-disk project), there is no version-resolved dependency set, so the CVE scan is skipped and logged rather than fabricated as clean.

### Stage 3 — Policy Enforcement

Policies enforce project-specific security constraints. See [Security Policies](#security-policies) for the rule schema. Blocking rules are enforced before any sandbox execution.

### Stage 4 — Isolated Execution

When sandboxing is enabled, code runs in an isolated, disposable environment:

- Temporary working directory (auto-cleaned after execution)
- Language runners for Go, Python, Node.js, and TypeScript (`ts-node`)
- Strict timeout enforcement (context deadline, default 10s)
- Scrubbed environment (`HOME=/tmp`, fixed `PATH`, `TMPDIR=/tmp`) so user secrets are never passed through
- Process-group management for clean teardown of the whole process tree
- Code files are written with restrictive permissions (0600)

> **Limitations:** memory (`max_memory_mb`) and network (`block_network`) are currently configuration values only — they are not yet enforced at the syscall level by the process runner. `Firecracker` is supported on Linux but today falls back to the process runner. Treat the process runner as a development convenience, not a hostile-code boundary.

---

## Security Scoring

The score is a deterministic, weighted sum of the four stage sub-scores:

```text
final = SAST*sast_weight + Deps*dep_weight + Policy*policy_weight + Sandbox*sandbox_weight
```

Default weights (normalised if they do not sum to 1.0):

| Weight | Default | Basis |
|---:|---:|---|
| `sast_weight` | 0.40 | 100 minus severity points per finding (CRITICAL 25 / HIGH 15 / MEDIUM 8 / LOW 3) |
| `dep_weight` | 0.30 | 100 minus severity points per vulnerability |
| `policy_weight` | 0.20 | 100 minus 20 per policy violation |
| `sandbox_weight` | 0.10 | skipped 100 · not-executed 50 · failed 0 · succeeded 100 |

### Verdicts

The numeric score is advisory. The verdict is authoritative and **fail-closed**, evaluated in this order — a hard condition can never be overridden by a high score:

| Priority | Condition | Verdict |
|---|---|---|
| 1 | Sandbox executed and failed | `EXECUTION_FAILED` |
| 2 | Mandatory check could not complete (fail-closed) | `ANALYSIS_INCOMPLETE` |
| 3 | Any CRITICAL finding or vulnerability | `BLOCKED` |
| 4 | Score ≥ `pass_threshold` (default 70) | `APPROVED` |
| 5 | Score 40–69 | `WARNING` |
| 6 | Score < 40 | `REJECTED` |

| Score | Verdict | Meaning |
|---:|---|---|
| 70–100 | `APPROVED` | No blocking issues; safe to use |
| 40–69 | `WARNING` | Review findings before using |
| 0–39 | `REJECTED` | Do not use |
| — | `BLOCKED` | A critical finding/vulnerability is present |
| — | `ANALYSIS_INCOMPLETE` | A mandatory check could not run (fail-closed) |
| — | `EXECUTION_FAILED` | Code ran in the sandbox and failed at runtime |

`fail_closed` defaults to **true**: when a mandatory check cannot complete, the result is `ANALYSIS_INCOMPLETE` rather than a partial score that could be read as safe. Only an explicit `fail_closed: false` opts into fail-open (and even then the verdict can never be `APPROVED` when analysis is incomplete).

Example report:

```text
Target: generated/main.go
Language: Go
Analysis ID: 8b7b9a2f

Stage scores:  SAST 100 · Deps 100 · Policy 60 · Sandbox —
Security score: 88 / 100
Final verdict: APPROVED

Policy violation:
  [BLOCKED_FUNCTION] Call to 'exec()' is blocked by security policy
  File: generated_code.go:42
```

---

## Output Formats

Use JSON or SARIF for automation and CI/CD pipelines:

```bash
elevated-cli audit --dir ./src --output json | jq '.final_score'
elevated-cli audit --dir ./src --output sarif
```

Example JSON response:

```json
{
  "id": "8b7b9a2f-...",
  "timestamp": "2026-08-16T05:38:09Z",
  "language": "go",
  "code_hash": "sha256...",
  "findings": [],
  "vulnerabilities": [],
  "policy_violations": [
    {
      "rule": "BLOCKED_FUNCTION",
      "description": "Call to 'exec()' is blocked by security policy.",
      "value": "exec"
    }
  ],
  "sandbox": {"executed": false, "skipped": true, "mode": "none"},
  "stage_scores": {"sast": 100, "deps": 100, "policy": 60, "sandbox": 100},
  "final_score": 88,
  "verdict": "APPROVED",
  "analysis_complete": true,
  "ai_provider": "openai",
  "ai_model": "gpt-4o"
}
```

SARIF 2.1.0 output is structured for GitHub Code Scanning dashboards.

---

## Configuration

Configuration can be supplied through:

1. Command-line flags
2. Environment variables
3. Configuration file (`.elevated-cli.yaml`)
4. Defaults

Priority order:

```text
CLI Flags > Environment Variables > Config File > Defaults
```

Environment variables use the `SECURE_AI_` prefix with dots replaced by underscores:

```bash
export SECURE_AI_AI_PROVIDER="openai"      # ai.provider
export SECURE_AI_AI_MODEL="gpt-4o"         # ai.model
export SECURE_AI_AI_API_KEY="..."          # ai.api_key
export SECURE_AI_SANDBOX_MODE="process"    # sandbox.mode
export SECURE_AI_SCORING_PASS_THRESHOLD="80"
export SECURE_AI_ANALYSIS_OSV_SCANNER="true"
```

### Schema

| Key | Default | Description |
|---|---|---|
| `ai.provider` | `openai` | `openai` \| `anthropic` \| `local` |
| `ai.model` | `gpt-4o` | Model name |
| `ai.api_key` | `""` | API key (prefer env vars) |
| `ai.endpoint` | `http://localhost:11434` | Endpoint for local/Ollama providers |
| `ai.timeout_sec` | `120` | LLM call timeout |
| `database.path` | `secure-ai.db` | SQLite database path |
| `sandbox.mode` | `process` | `process` \| `firecracker` \| `docker` \| `skip` |
| `sandbox.timeout_sec` | `10` | Execution timeout |
| `sandbox.max_memory_mb` | `256` | Memory cap (config only today) |
| `sandbox.block_network` | `true` | Network deny (config only today) |
| `output.format` | `rich` | `rich` \| `json` \| `sarif` \| `plain` |
| `output.show_code` | `false` | Include code snippets in reports |
| `output.audit_db` | `secure-ai.db` | SQLite path for scan history |
| `logger.level` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `logger.format` | `console` | `json` \| `console` |
| `logger.file` | `""` | Optional log file |
| `policy.file` | `.elevated-cli.yaml` | Policy rules file |
| `scoring.sast_weight` | `0.40` | SAST stage weight |
| `scoring.dep_weight` | `0.30` | Dependency stage weight |
| `scoring.policy_weight` | `0.20` | Policy stage weight |
| `scoring.sandbox_weight` | `0.10` | Sandbox stage weight |
| `scoring.pass_threshold` | `70` | Score for `APPROVED` |
| `scoring.fail_closed` | `true` | Fail closed on incomplete analysis |
| `analysis.govulncheck` | `true` | Enable govulncheck scanning |
| `analysis.osv_scanner` | `true` | Enable osv-scanner scanning |
| `analysis.custom_ast_rules` | `true` | Enable custom AST checks |

---

## Security Policies

Policies are defined in the `policy` section of `.elevated-cli.yaml`:

```yaml
policy:
  file: .elevated-cli.yaml
  rules:
    blocked_imports:
      - os/exec
      - syscall
      - unsafe
      - net/http
    blocked_functions:
      - eval
      - exec
      - system
    require_error_handling: true
```

Rules:

| Rule | Behavior |
|---|---|
| `blocked_imports` | Blocklisted package paths. Go matches exact path or subpath (e.g. `os/exec` catches `os/exec/...`); other languages match on the line. |
| `blocked_functions` | Blocked calls. Matches the bare function name (`Command`), the qualified call (`exec.Command`), or the package prefix (`exec`). |
| `require_error_handling` | Flags Go code that discards errors with `_`. |
| `max_cyclomatic_complexity` | Declared in the schema (default 15); complexity measurement is not yet enforced. |

A critical policy violation or critical SAST finding forces a `BLOCKED` verdict regardless of the numeric score.

---

## Audit History

Every pipeline run is stored in SQLite (schema migrations live in `internal/database/migrations`):

```bash
elevated-cli history --last 20
elevated-cli history --date 2025-04-24
elevated-cli history --id <scan-id>
```

Reports store the code as a SHA-256 hash plus provider, model, stage scores, verdict, and findings. Prompt text is stored for auditability — configure `logger` and review the stored fields if prompt redaction is required for your environment.

---

## Exit Codes

| Exit Code | Meaning |
|---:|---|
| `0` | Success |
| `1` | Error (invalid usage, pipeline failure, config error) |
| `2` | A file was **rejected** (`REJECTED` verdict) |

`generate` and `audit` exit with code `2` when the final verdict is `REJECTED`, so CI can gate on it.

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

ElevatedCLI follows these principles:

- **Fail closed:** If a required security control fails, block execution.
- **Least privilege:** Sandboxed workloads receive minimal privileges.
- **Deny by default:** Network access and dangerous operations require explicit approval.
- **Defense in depth:** Use multiple layers — syntax checks, SAST, dependency scanning, policies, and sandboxing.
- **No direct host execution:** Untrusted code must not run directly on the developer machine or CI host.
- **Auditability:** Record decisions, findings, and execution metadata.
- **Secret protection:** Redact secrets from logs and reports; subprocesses receive a scrubbed environment.
- **Deterministic policy decisions:** Identical inputs always produce identical scores and verdicts.

---

## Architecture

```text
elevated-cli/
├── cmd/
│   └── elevated-cli/
│       ├── main.go
│       ├── version.go
│       └── commands/
│           ├── root.go        # root command, global flags, config/logger init
│           ├── generate.go    # AI generation + pipeline
│           ├── audit.go       # file/dir auditing + CVE scanning
│           ├── history.go     # history + config commands
│           └── common.go      # pipeline wiring, report printing
│
├── internal/
│   ├── ai/                    # OpenAI, Anthropic, local/Ollama clients + prompt builder
│   ├── config/                # Viper-based configuration loading
│   ├── database/              # SQLite audit history + migrations
│   ├── logger/                # zap structured logging
│   ├── output/                # report formatters (rich/json/sarif/plain) + templates
│   ├── sandbox/               # process_runner, firecracker_runner, resource_governor
│   ├── security/              # pipeline, static_analyzer, dependency_auditor,
│   │   │                      # policy_engine, scoring
│   │   └── scoring/           # deterministic scoring algorithm
│   └── utils/                 # filesystem helpers
│
├── pkg/
│   └── security/              # shared types (Finding, Vulnerability, Verdict, Report…)
│
├── configs/                   # sample configs (default/development/enterprise/production)
├── docs/                      # architecture, guides, and security documentation
├── test/
├── go.mod
├── go.sum
├── Makefile
├── README.md
└── LICENSE
```

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
gosec ./internal/... ./cmd/... ./pkg/...
govulncheck ./...
```

### Build

```bash
go build -o bin/elevated-cli ./cmd/elevated-cli
```

### Build with Version Info

```bash
go build -ldflags="-X main.Version=1.0.0 -X main.Commit=$(git rev-parse --short HEAD) -X main.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o bin/elevated-cli ./cmd/elevated-cli
```

### Run Locally

```bash
go run ./cmd/elevated-cli --help
```

### Makefile

```bash
make build           # go build -o elevated-cli ./cmd/elevated-cli
make build-release   # build with injected version/commit/date
make test            # go test ./... -race -count=1 -v
make gosec           # gosec ./...
make vulncheck       # govulncheck ./...
make all-checks      # fmt + vet + lint + test + gosec + vulncheck
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
- Sandbox cleanup
- Environment and secret isolation
- Security-score calculation (including fail-closed verdicts)
- Audit-log secret redaction
- CLI exit codes
- End-to-end verification flow

---

## Roadmap

### P0 — Required Before Untrusted Execution

- [x] Enforce fail-closed verification behavior
- [x] Prevent direct host execution (no sandbox falls back to nothing)
- [ ] Implement verified sandbox isolation (Firecracker/gVisor)
- [ ] Enforce timeout, memory, CPU, process, and output limits (timeout done; memory/CPU/network pending)
- [ ] Deny network access by default (config exists; syscall enforcement pending)
- [ ] Restrict filesystem and environment-variable access (env scrubbing done; fs/namespace enforcement pending)
- [ ] Add path traversal and temporary-file protections (temp-dir isolation and containment checks done)
- [ ] Ensure secrets never appear in logs or reports

### P1 — Secure MVP

- [x] Cobra CLI commands and Viper configuration
- [x] LLM provider abstraction
- [x] Safe structured AI response parsing
- [x] Go syntax validation
- [x] `gosec` integration
- [x] `govulncheck` and OSV-Scanner integration
- [x] Configurable policy engine
- [x] Deterministic security scoring
- [x] Human-readable and JSON reports (plus SARIF/plain)
- [x] Structured logging
- [x] SQLite audit storage
- [x] Unit and integration tests

### P2 — Production Hardening

- [ ] Firecracker microVM support (stub currently falls back to process runner)
- [ ] gVisor runtime support
- [ ] Docker sandbox isolation
- [ ] Enforce memory/CPU/network limits in the process runner
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

ElevatedCLI is a security-assistance tool, not a guarantee of secure software. Automated analysis can miss vulnerabilities, produce false positives, and depend on the reliability of external tools and sandbox runtimes.

Always use code review, testing, dependency controls, least-privilege deployment, and appropriate security practices before deploying AI-generated code.
