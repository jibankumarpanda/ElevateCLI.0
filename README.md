# ElevateCLI

> Generate, inspect, and verify AI-generated code from the terminal.

[![Go Version](https://img.shields.io/badge/go-1.25-blue.svg)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`elevated-cli` is a Go-based command-line tool that generates code through supported LLM providers and runs the result through a multi-stage verification pipeline:

```text
Static analysis → Dependency audit → Policy enforcement → Controlled execution
```

It produces an explainable verdict, a deterministic security score from 0–100, machine-readable reports, and a local audit trail.

```text
Generate code faster.
Inspect and verify it before use.
Use hardened isolation before executing untrusted code.
```

> 🚧 **Project status: Beta / development.** ElevateCLI provides automated verification and controlled local execution. It is not production-ready for hostile or untrusted code until hardened isolation and enforced CPU, memory, filesystem, process, and network controls are implemented and independently tested.

> ⚠️ **Security notice:** AI-generated code is untrusted input. Static analysis, dependency scans, policies, scores, and controlled execution reduce risk; they do not prove that code is secure. A positive score or `APPROVED` verdict does not mean code is safe to execute on the host or deploy to production. Do not execute untrusted code without a verified hardened isolation runtime such as Firecracker or gVisor.

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
- [Audit Data and Privacy](#audit-data-and-privacy)
- [Audit History](#audit-history)
- [Platform Support](#platform-support)
- [Language Support](#language-support)
- [External Tool Compatibility](#external-tool-compatibility)
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
- [Disclaimer](#disclaimer)

---

## Features

### Implemented

- Go-based CLI named `elevated-cli`
- Cobra commands and Viper configuration
- AI-provider abstraction for:
  - OpenAI (via `go-openai` SDK)
  - Anthropic (via raw HTTP client)
  - Local/Ollama-compatible endpoints (via HTTP)
- Prompt-to-code generation with Markdown code-block extraction
- Security verification pipeline:
  1. Static analysis using `gosec`, Go AST rules, and language-specific patterns
  2. Dependency auditing using `govulncheck` and `osv-scanner`
  3. Configurable policy enforcement for blocked imports, functions, and error handling
  4. Controlled process execution using Go `os/exec`
- Deterministic 0–100 security scoring
- Fail-closed handling for configured mandatory scanner failures
- Report formats:
  - Rich terminal output
  - JSON
  - SARIF
  - Plain text
- Structured console or JSON logging using `zap`
- SQLite-backed local scan history
- Existing-file and directory auditing
- Config inspection and updates
- CI-friendly JSON and SARIF reports

### Current Execution Limitations

The current process runner provides **controlled host-process execution**, not a production-grade security sandbox.

It provides:

- Temporary working-directory creation and cleanup
- Restricted generated-code file permissions (0600)
- Timeout handling via `context.Context`
- Scrubbed environment variables (minimal `HOME`, `PATH`, `TMPDIR`)
- Process-group termination for child-process cleanup
- Path-traversal prevention for generated files
- Network isolation on Linux via unprivileged user+network namespaces when `block_network: true` (fails closed if isolation is unavailable)
- Memory-limit enforcement on Linux via `prlimit --as` when `max_memory_mb` is set (fails closed if the limit cannot be enforced)

It does **not** provide a hardened isolation boundary against hostile code. In particular, it does not currently enforce:

- Hardware virtualization or a microVM boundary
- Full container isolation (user namespaces are used only to create an isolated network namespace for `block_network`)
- Kernel-level filesystem isolation
- Syscall filtering (seccomp)
- Enforced CPU limits
- Enforced process-count limits (the memory limit is enforced via `RLIMIT_AS`)
- Prevention of kernel-level, host-level, or same-user attacks

> The process runner is intended only for controlled local development. Do not treat it as a sandbox for malicious or fully untrusted code.

### Planned

- Firecracker microVM execution
- gVisor execution support
- No-fallback hardened sandbox selection
- Runtime-enforced CPU, memory, process, output, filesystem, and network limits
- SBOM generation
- Signed releases
- Reproducible builds
- CI security-gate integration
- Policy bundles and policy versioning
- Audit retention controls
- Metrics and observability
- Stronger multi-language parsers and analyzers
- Plugin architecture for additional analyzers

> Planned features must not be treated as available until implemented, tested, and included in a release.

---

## How It Works

AI coding tools can accelerate development, but generated code may contain:

- Hardcoded credentials and API keys
- SQL injection and command-injection risks
- Unsafe package imports
- Vulnerable third-party dependencies
- Insecure deserialization
- Dangerous shell or process execution
- Unsafe filesystem access
- Excessive permissions
- Unrestricted network access
- Logic flaws that automated scanners cannot detect

ElevateCLI places verification between AI generation and any decision to use or execute generated code:

```text
Developer Prompt
      │
      ▼
AI Code Generation
(OpenAI / Anthropic / Ollama)
      │
      ▼
Code Extraction and Syntax Validation
      │
      ▼
Stage 1 — Static Analysis
(gosec + Go AST + language patterns)
      │
      ▼
Stage 2 — Dependency Audit
(govulncheck / osv-scanner)
      │
      ▼
Stage 3 — Policy Enforcement
(blocked imports, calls, and project rules)
      │
      ▼
Stage 4 — Controlled Process Execution
(optional; development mode only)
      │
      ▼
Security Score and Verdict
      │
      ▼
Terminal / JSON / SARIF Report + SQLite Audit History
```

Stages 1–3 may run in parallel. Execution is performed only after verification reaches the execution step and should not occur when a blocking condition is found.

---

## Installation

### Build from Source

```bash
git clone https://github.com/jibankumarpanda/ElevateCLI.git
cd ElevateCLI

go build -o bin/elevated-cli ./cmd/elevated-cli
```

Verify the binary:

```bash
./bin/elevated-cli --help
```

### Install with Go

> The module path is `github.com/jibankumarpanda/ElevateCLI.0`. Confirm this matches your `go.mod` before publishing.

```bash
go install github.com/jibankumarpanda/ElevateCLI.0/cmd/elevated-cli@latest
```

### Prerequisites

- Go 1.25 or later
- Git
- Optional language runtimes for execution:
  - Python for Python code
  - Node.js for JavaScript code
  - `ts-node` for TypeScript code

### Optional Security Tools

The following tools are used when their corresponding integrations are enabled. Under fail-closed configuration, a required tool that is unavailable produces an `ANALYSIS_INCOMPLETE` result rather than a clean result.

```bash
# Go static security analysis
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Go vulnerability scanning
go install golang.org/x/vuln/cmd/govulncheck@latest

# Multi-language dependency vulnerability scanning
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

### Hardened Sandbox Runtimes

Firecracker and gVisor are planned hardened execution backends.

- Firecracker provides Linux microVM-based isolation.
- gVisor provides an additional isolation layer for containerized workloads.
- The current `os/exec` process runner is **not** a substitute for either.

If a future configuration requests Firecracker or gVisor but the runtime is unavailable, ElevateCLI should fail closed rather than silently falling back to host process execution.

---

## Quick Start

### 1. Create a Configuration File

ElevateCLI searches for `.elevated-cli.yaml` in the current directory or home directory unless `--config` is supplied.

```bash
touch .elevated-cli.yaml
```

Example configuration:

```yaml
ai:
  provider: openai # openai | anthropic | local
  model: gpt-4o
  api_key: "" # Prefer environment variables instead
  endpoint: http://localhost:11434
  timeout_sec: 120

sandbox:
  mode: process # process | firecracker | docker | skip
  timeout_sec: 10
  max_memory_mb: 256 # Enforced on Linux via prlimit; fails closed when it cannot be enforced
  block_network: true # Runtime-enforced on Linux via user+network namespaces; fails closed when unavailable

output:
  format: rich # rich | json | sarif | plain
  show_code: false
  audit_db: secure-ai.db # SQLite audit-database path

audit:
  store_prompts: true # Retain raw prompts in history (disable for strict retention)
  store_generated_code: true # Retain generated source in history (disable for strict retention)
  redact_secrets: true # Redact detected credentials before anything is written to disk

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

Set API credentials through environment variables:

```bash
export SECURE_AI_AI_API_KEY="your-api-key"
```

> Never commit API keys, credentials, tokens, `.env` files, or personal configuration files to source control.

### 2. Generate and Verify Code

```bash
elevated-cli generate \
  --prompt "Create a Go HTTP API with a health endpoint" \
  --lang go
```

### 3. Request Controlled Local Execution

```bash
elevated-cli generate \
  --prompt "Read a CSV file and print the row count" \
  --lang python \
  --run
```

> `--run` may execute code through the current host process runner. Use it only for code you are willing to run in a controlled local-development environment. It is not suitable for hostile or unknown code.

### 4. Audit Existing Code

```bash
# Audit a single file
elevated-cli audit --file ./mycode.go

# Audit a directory recursively
elevated-cli audit --dir ./src --lang python
```

### 5. View Audit History

```bash
elevated-cli history --last 10
elevated-cli history --date 2025-04-24
elevated-cli history --id <scan-id>
```

---

## Commands

| Command | Description |
|---|---|
| `generate` | Generate code from an AI provider and verify it through the pipeline |
| `audit` | Verify an existing file or directory |
| `history` | Browse previous audit reports stored in SQLite |
| `config` | Display or modify ElevateCLI configuration |

### Global Flags

| Flag | Description |
|---|---|
| `--config <path>` | Use an explicit configuration file |
| `--output <format>` | `rich`, `json`, `sarif`, or `plain` |
| `--no-sandbox` | Skip controlled execution; this does not establish runtime safety |
| `--verbose` | Enable debug logging |

### `generate`

```bash
elevated-cli generate --prompt "..." --lang go
```

| Flag | Description |
|---|---|
| `-p, --prompt` | Natural-language request for code generation; required |
| `-l, --lang` | `go`, `python`, `javascript`, or `typescript`; default `go` |
| `-m, --model` | Override the configured LLM model |
| `--sandbox` | Requested mode: `firecracker`, `process`, or `docker` |
| `--run` | Request controlled execution after verification |
| `--dry-run` | Print the generated prompt without calling an LLM |
| `-o, --output` | `rich`, `json`, `sarif`, or `plain` |

### `audit`

```bash
elevated-cli audit --dir ./src
```

| Flag | Description |
|---|---|
| `-f, --file` | Path to one file |
| `-d, --dir` | Path to a directory to audit recursively |
| `-l, --lang` | Language override; otherwise use extension detection where supported |
| `-o, --output` | `rich`, `json`, `sarif`, or `plain` |

### `history`

```bash
elevated-cli history --last 10
```

| Flag | Description |
|---|---|
| `-n, --last` | Number of recent records to show |
| `-d, --date` | Filter by `YYYY-MM-DD` |
| `--id` | Show a complete report for a scan ID |

### `config`

```bash
elevated-cli config --show
elevated-cli config --set ai.model=gpt-4o
```

| Flag | Description |
|---|---|
| `--show` | Print resolved configuration |
| `--set` | Set a configuration value using `key=value` (currently prints instructions; does not write to config file) |

---

## Verification Pipeline

Every target is assessed through four stages.

### Stage 0 — Code Extraction and Validation

Before security analysis, ElevateCLI should:

- Extract code from model responses or source files
- Detect the selected or inferred language
- Validate supported syntax where implemented
- Return actionable parsing errors
- Prevent execution if extraction or validation fails

Malformed model output, unsupported formats, and invalid syntax should never be treated as a clean scan.

### Stage 1 — Static Security Analysis

#### Go

Go verification can combine:

- `gosec`
- Custom `go/ast` and `go/parser` rules
- Pattern-based checks

Examples of detectable risks include:

- Hardcoded secrets
- Dangerous shell or command execution
- Unsafe filesystem operations
- `os.RemoveAll` misuse
- Unsafe dynamic network access
- `net.Dial` and `http.Get` usage where restricted
- Unsafe file reads
- SQL injection patterns
- Unsafe file permissions
- Path traversal indicators
- Ignored errors
- Dangerous imports

#### Python

Pattern checks may identify:

- `eval(`
- `exec(`
- `os.system(`
- `pickle.loads`
- `subprocess.call(`
- `shell=True`
- Hardcoded passwords and tokens

#### JavaScript and TypeScript

Pattern checks may identify:

- `eval(`
- `innerHTML`
- `document.write(`
- `dangerouslySetInnerHTML`
- Unsafe use of `process.env`

> Pattern-based checks are useful signals, not complete language-specific security analysis.

### Stage 2 — Dependency Audit

The dependency auditor can inspect dependency manifests and lockfiles such as:

```text
go.mod
go.sum
package-lock.json
npm-shrinkwrap.json
yarn.lock
pnpm-lock.yaml
requirements.txt
Pipfile.lock
poetry.lock
pyproject.toml
Cargo.lock
composer.lock
Gemfile.lock
```

- `govulncheck` audits Go modules.
- `osv-scanner` audits supported dependency files across ecosystems.
- If `go.mod` exists, `go.sum` can be treated as part of the same Go-module analysis.
- If no dependency manifest or lockfile exists, the tool cannot derive a version-resolved dependency set. It must report that limitation rather than claim a clean dependency scan.
- If a configured mandatory scanner is unavailable, the result should be marked incomplete under fail-closed mode.

### Stage 3 — Policy Enforcement

Policies apply project-specific restrictions before execution.

Example policy objectives:

- Disallow dangerous imports
- Disallow shell execution
- Restrict unsafe functions
- Require error handling
- Restrict sensitive network usage
- Restrict unsafe filesystem access
- Require approved dependency sources

Blocking policy violations must prevent execution. A policy rule configured with `action: block` must never be overridden by a high numerical score.

### Stage 4 — Controlled Process Execution (development mode)

When execution is explicitly requested and no blocking condition is present, the current execution backend uses a controlled Go `os/exec` process on the host operating system.

Current safeguards include:

- Disposable temporary working directory
- Restrictive generated-code file permissions (0600)
- Timeout through `context.Context`
- Scrubbed environment variables
- Controlled `HOME`, `PATH`, and `TMPDIR` values
- Process-group teardown
- Path-traversal prevention for generated files
- Captured stdout, stderr, exit code, and duration

#### Important Limitations

The current process runner runs on the host operating system. It is **not a hardened sandbox**.

The following controls are not yet a verified part of the process runner:

- MicroVM isolation
- Container isolation
- User namespaces
- Mount namespaces
- Seccomp filtering
- Cgroups
- Enforced CPU limits
- Enforced memory limits
- Enforced process limits
- Enforced output limits
- Enforced network blocking at the kernel level
- Restricted host filesystem access at kernel level

For production execution of untrusted code, use a verified isolation system such as Firecracker, gVisor, or another hardened environment with strong runtime controls.

### Firecracker Fallback Behavior

`firecracker` is accepted as a configuration value, but microVM execution is not yet operational. When `sandbox.mode: firecracker` is selected, ElevateCLI **fails closed**: the requested microVM boundary is never silently replaced with host `os/exec` execution. The pipeline returns an `ANALYSIS_INCOMPLETE` verdict with a clear explanation that the Firecracker runtime is unavailable, instead of claiming a controlled run happened inside a microVM.

> The `docker` sandbox mode is likewise not implemented and fails closed with `ANALYSIS_INCOMPLETE` rather than silently running on the host.

Once microVM orchestration is implemented (via `firecracker-go-sdk`), a requested `sandbox.mode: firecracker` will boot a real microVM. Until then, no configuration value can silently downgrade to the process runner: the only way to use the process runner is to configure `sandbox.mode: process` explicitly.

### Execution-Skipped Behavior

When `--no-sandbox` is used, or when execution is not requested:

- The target code is not executed.
- The report marks execution as skipped or not attempted.
- Skipped execution does not establish runtime safety.
- A project policy may require execution before approval.
- If execution is mandatory and unavailable, the result should be non-approving, such as `ANALYSIS_INCOMPLETE`.

> Do not claim that code passing static analysis and policy checks without execution is fully verified. Execution-skipped results should be treated as partial verification only.

---

## Security Scoring

ElevateCLI calculates a deterministic score from 0–100 using weighted stage scores:

```text
final_score =
  (SAST × sast_weight) +
  (Dependencies × dep_weight) +
  (Policy × policy_weight) +
  (Execution × sandbox_weight)
```

The default weights are normalized if they do not total `1.0`.

| Weight | Default | Example basis |
|---:|---:|---|
| `sast_weight` | 0.40 | Severity deductions from static-analysis findings |
| `dep_weight` | 0.30 | Severity deductions from dependency vulnerabilities |
| `policy_weight` | 0.20 | Policy-violation deductions |
| `sandbox_weight` | 0.10 | Controlled-execution outcome |

Example severity deductions:

| Severity | Example deduction |
|---|---:|
| Critical | 25 |
| High | 15 |
| Medium | 8 |
| Low | 3 |

### Verdict Rules

The score is advisory. The verdict is authoritative.

| Priority | Condition | Verdict |
|---:|---|---|
| 1 | Mandatory analysis cannot complete under fail-closed mode | `ANALYSIS_INCOMPLETE` |
| 2 | A critical SAST finding or critical dependency vulnerability exists | `BLOCKED` |
| 3 | A policy rule configured as blocking is violated | `BLOCKED` |
| 4 | Required execution backend is unavailable | Non-approving result |
| 5 | Controlled execution was attempted and failed | `EXECUTION_FAILED` |
| 6 | No blocking conditions and score meets threshold | `APPROVED` |
| 7 | No blocking conditions but score requires review | `WARNING` or `REJECTED` |

`APPROVED` means enabled verification controls completed and found no blocking condition. It does **not** mean that the code is proven secure, safe to execute on the host, or approved for production deployment.

### Score Interpretation

| Score | Typical verdict | Meaning |
|---:|---|---|
| 70–100 | `APPROVED` | No blocking findings were detected by enabled checks. Manual review remains required. |
| 40–69 | `WARNING` | Findings or limitations require review before use. |
| 0–39 | `REJECTED` | Significant risks were detected. Do not use without remediation. |
| — | `BLOCKED` | A critical finding or blocking policy violation exists. |
| — | `ANALYSIS_INCOMPLETE` | A required verification control did not complete. |
| — | `EXECUTION_FAILED` | Controlled execution failed, timed out, or exited unsuccessfully. |

### Correct Scoring Example

```text
Target: generated/main.go
Language: Go
Analysis ID: 8b7b9a2f

Stage scores: SAST 100 · Dependencies 100 · Policy 60 · Execution NOT RUN
Security score: 92 / 100
Final verdict: BLOCKED

Blocking policy violation:
  [BLOCKED_FUNCTION]
  Call to "exec()" is prohibited by security policy.
  File: generated/main.go:42
  Action: Code execution was not attempted.
```

Although the numeric score is 92, the final verdict is `BLOCKED` because a blocking policy violation cannot be overridden by the score.

### Blocking Conditions

A policy violation configured with `action: block`, a critical SAST finding, a critical dependency vulnerability, a failed required sandbox, or incomplete mandatory analysis always prevents approval regardless of the numeric score.

---

## Output Formats

ElevateCLI supports terminal-friendly and machine-readable reports.

```bash
elevated-cli audit --dir ./src --output json
elevated-cli audit --dir ./src --output sarif
elevated-cli audit --dir ./src --output plain
```

### Example JSON Report

```json
{
  "id": "8b7b9a2f-...",
  "timestamp": "2026-08-16T05:38:09Z",
  "prompt": "Create a Go HTTP API with a health endpoint",
  "language": "go",
  "code_hash": "sha256...",
  "findings": [],
  "vulnerabilities": [],
  "policy_violations": [
    {
      "rule": "BLOCKED_FUNCTION",
      "description": "Call to exec() is prohibited by security policy.",
      "file": "generated/main.go",
      "line": 42,
      "value": "exec"
    }
  ],
  "sandbox": {
    "executed": false,
    "success": false,
    "exit_code": 0,
    "mode": "process",
    "skipped": true,
    "skip_reason": "Blocked by policy violation"
  },
  "stage_scores": {
    "sast": 100,
    "deps": 100,
    "policy": 60,
    "sandbox": 100
  },
  "final_score": 92,
  "verdict": "BLOCKED",
  "analysis_complete": true,
  "ai_provider": "openai",
  "ai_model": "gpt-4o"
}
```

> Exact JSON field names match the `Report` struct in `pkg/security/types.go`. Update this example if the report model changes.

### SARIF

SARIF output is intended for security-reporting tools and code-scanning systems that support SARIF 2.1.0.

---

## Configuration

Configuration can be supplied through:

1. Command-line flags
2. Environment variables
3. `.elevated-cli.yaml`
4. Built-in defaults

Priority order:

```text
CLI flags > Environment variables > Configuration file > Defaults
```

Environment variables use the `SECURE_AI_` prefix and replace dots with underscores:

```bash
export SECURE_AI_AI_PROVIDER="openai"
export SECURE_AI_AI_MODEL="gpt-4o"
export SECURE_AI_AI_API_KEY="..."
export SECURE_AI_SANDBOX_MODE="process"
export SECURE_AI_SCORING_PASS_THRESHOLD="80"
export SECURE_AI_ANALYSIS_OSV_SCANNER="true"
```

### Configuration Schema

| Key | Default | Description |
|---|---|---|
| `ai.provider` | `openai` | `openai`, `anthropic`, or `local` |
| `ai.model` | `gpt-4o` | Selected model |
| `ai.api_key` | `""` | API credential; prefer environment variables |
| `ai.endpoint` | `http://localhost:11434` | Local provider endpoint |
| `ai.timeout_sec` | `120` | LLM request timeout |
| `sandbox.mode` | `process` | `process`, `firecracker`, `docker`, or `skip` |
| `sandbox.timeout_sec` | `10` | Controlled-execution timeout |
| `sandbox.max_memory_mb` | `256` | Enforced on Linux via `prlimit --as`; fails closed when it cannot be enforced |
| `sandbox.block_network` | `true` | Enforced on Linux via user+network namespaces; fails closed when isolation is unavailable |
| `output.format` | `rich` | `rich`, `json`, `sarif`, or `plain` |
| `output.show_code` | `false` | Include source snippets in report output |
| `output.audit_db` | `secure-ai.db` | SQLite audit-database path |
| `audit.store_prompts` | `true` | Retain raw prompts in scan history |
| `audit.store_generated_code` | `true` | Retain generated source in scan history |
| `audit.redact_secrets` | `true` | Redact detected credentials before writing history |
| `logger.level` | `info` | `debug`, `info`, `warn`, or `error` |
| `logger.format` | `console` | `console` or `json` |
| `logger.file` | `""` | Optional log-file path |
| `scoring.sast_weight` | `0.40` | Static-analysis score weight |
| `scoring.dep_weight` | `0.30` | Dependency score weight |
| `scoring.policy_weight` | `0.20` | Policy score weight |
| `scoring.sandbox_weight` | `0.10` | Execution score weight |
| `scoring.pass_threshold` | `70` | Approval threshold (0–100) |
| `scoring.fail_closed` | `true` | Do not approve when mandatory analysis is incomplete |
| `analysis.govulncheck` | `true` | Enable Go vulnerability analysis |
| `analysis.osv_scanner` | `true` | Enable OSV dependency scanning |
| `analysis.custom_ast_rules` | `true` | Enable custom AST checks |
| `policy.file` | `.elevated-cli.yaml` | Path to the policy file (currently self-referencing; inline rules in `policy.rules` take precedence) |

> `database.path` also exists as a config key with the same default (`secure-ai.db`), but `output.audit_db` is the key actively used for opening the SQLite database. If both are present, `output.audit_db` takes precedence for audit operations.

---

## Security Policies

Policies define organization-specific restrictions.

Example inline policy configuration:

```yaml
policy:
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

| Rule | Behavior |
|---|---|
| `blocked_imports` | Denies listed package paths or import patterns |
| `blocked_functions` | Denies listed function calls or qualified function patterns |
| `require_error_handling` | Flags Go code that discards errors using `_` |
| `max_cyclomatic_complexity` | Flags Go functions whose cyclomatic complexity exceeds the threshold; `0` disables |

A policy should support an action such as `warn` or `block`. Any rule configured with `block` should prevent execution and prevent an approving verdict.

---

## Audit Data and Privacy

ElevateCLI stores audit records in SQLite. Audit data can be sensitive because it may reveal source paths, project structure, model usage, security findings, and developer activity.

### Current Behavior (Honest Disclosure)

By default, the current implementation stores:

- Scan ID and timestamp
- Raw user prompts (in the `prompt` column and within the full report JSON blob)
- Generated source code (within the report JSON blob)
- Provider and model metadata
- Language and code hash (SHA-256)
- Static-analysis findings
- Dependency vulnerabilities
- Policy violations
- Execution metadata
- Stage scores and final score
- Final verdict
- Tool versions

The following are **not** stored:

- API keys, tokens, or cookies
- Environment variables or secret values

### Retention and Redaction Controls

The default behavior above can be tightened through the `audit` configuration
section. These controls are implemented and honoured every time a report is
written to the audit database:

```yaml
audit:
  store_prompts: false          # drop the prompt column and prompt from the stored report
  store_generated_code: false   # drop generated source from the stored report
  redact_secrets: true          # rewrite detected credentials as [REDACTED] before writing
```

`redact_secrets` is enabled by default: known credential shapes (API keys,
password/secret/token assignments, bearer tokens, AWS keys, PEM private keys)
are replaced with `[REDACTED]` in stored prompts, generated source, findings,
and sandbox output before anything touches disk. The in-memory report used for
terminal/JSON/SARIF output is never modified.

> **Privacy note:** Prompts and generated code are stored by default. Prompts
> may contain sensitive information such as business logic, internal API
> designs, or proprietary requirements. For strict data-retention orgs, set
> `audit.store_prompts: false` and `audit.store_generated_code: false`.

### Operational Recommendations

- Store SQLite files in user-private directories.
- Apply restrictive filesystem permissions to the database file.
- Encrypt backups.
- Restrict database access by file-system permissions.
- Set organizational data-retention policies.
- Do not treat log redaction as a substitute for secret-management controls.

---

## Audit History

Each pipeline run can be saved to SQLite.

```bash
elevated-cli history --last 20
elevated-cli history --date 2025-04-24
elevated-cli history --id <scan-id>
```

Audit history supports troubleshooting, review, comparisons, and operational visibility. Treat the audit database as potentially sensitive data.

---

## Platform Support

| Platform | CLI | Static analysis | Controlled process runner | Firecracker microVM | gVisor |
|---|---:|---:|---:|---:|---:|
| Linux | Supported | Supported when tools are installed | Development only | Planned / Linux-specific | Planned |
| macOS | Supported | Supported when tools are installed | Development only | Not supported | Not supported |
| Windows | Supported where Go and external tools are available | Supported when tools are installed | Development only | Not supported | Not supported |

> Exact behavior depends on installed scanners, language runtimes, permissions, and operating-system process-management behavior. The current process runner is not a hardened isolation boundary on any platform.

---

## Language Support

| Language | Code extraction | Syntax validation | Static analysis | Dependency audit | Controlled execution | Maturity |
|---|---:|---:|---:|---:|---:|---|
| Go | Yes | Verify from source | `gosec` + AST rules | `govulncheck` + OSV | Yes | Primary |
| Python | Yes | Verify from source | Pattern-based checks | OSV lockfile scan | Yes | Experimental |
| JavaScript | Yes | Verify from source | Pattern-based checks | OSV lockfile scan | Yes | Experimental |
| TypeScript | Yes | Verify from source | Pattern-based checks | OSV lockfile scan | Requires `ts-node` | Experimental |

> Multi-language support should be considered experimental until each language has robust parsing, dedicated security analysis, test coverage, and hardened isolated execution.

---

## External Tool Compatibility

| Tool | Purpose | Needed when |
|---|---|---|
| Go | Build, Go parsing, Go execution | Working with Go projects |
| `gosec` | Go static application security testing | Go SAST is enabled |
| `govulncheck` | Go module vulnerability scanning | Go dependency audit is enabled |
| `osv-scanner` | Multi-ecosystem dependency scanning | OSV scanning is enabled |
| Python | Python execution | Executing Python code |
| Node.js | JavaScript execution | Executing JavaScript code |
| `ts-node` | TypeScript execution | Executing TypeScript code |

When a configured mandatory tool is missing, fail-closed mode returns an incomplete result rather than reporting a clean scan. This is verified in the source: `gosec` and `govulncheck` return errors on missing binaries that propagate to `ANALYSIS_INCOMPLETE` verdicts.

Pin, test, and document compatible external-tool versions in CI before release.

---

## Exit Codes

| Exit code | Meaning |
|---:|---|
| `0` | Verification completed with a non-blocking result (`APPROVED` or `WARNING`) |
| `1` | CLI, input, configuration, database, or internal error |
| `2` | Security pipeline returned `REJECTED` or `BLOCKED` verdict |
| `3` | `ANALYSIS_INCOMPLETE` — a required verification control did not complete under fail-closed mode |
| `4` | `EXECUTION_FAILED` — the sandbox ran the code and it failed at runtime |

Every hard-stop verdict exits non-zero so CI/CD can gate on the outcome and
distinguish the cause via the specific code. When auditing a directory, the
highest (most severe) exit code across all files is returned.

---

## Threat Model

ElevateCLI treats the following as untrusted:

- AI-generated source code
- AI model output
- User prompts
- Third-party dependencies
- External scanner output
- Configuration from untrusted environments
- Files in scanned projects unless explicitly trusted

The project aims to reduce risk from:

- Unsafe code generation
- Command injection
- SQL injection
- Path traversal
- Hardcoded credentials
- Secret leakage
- Vulnerable dependencies
- Unsafe imports and APIs
- Resource exhaustion
- Policy bypasses
- False "safe" results caused by skipped analysis

### Out of Scope

ElevateCLI cannot guarantee that code is secure or protect against every threat, including:

- Unknown vulnerabilities
- Scanner blind spots and false negatives
- Compromised third-party dependencies
- Compromised LLM providers
- Compromised host operating systems
- Compromised sandbox runtimes
- Kernel vulnerabilities
- Logic bugs outside scanner coverage
- Unsafe human approvals
- Data leakage through prompts, logs, reports, or databases if retention is not configured carefully

---

## Security Principles

- **Fail closed:** A mandatory security control that cannot complete should not result in an approving verdict.
- **Defense in depth:** Use parsing, SAST, dependency auditing, policies, scoring, runtime controls, and manual review together.
- **Least privilege:** Future hardened runtimes should grant only minimal filesystem, network, process, and environment access.
- **Deny by default:** Network access and dangerous actions should require explicit policy approval.
- **No unverified host execution:** By default, ElevateCLI does not execute generated code unless execution is explicitly requested. The current process runner executes code on the host and is only suitable for controlled local development. Production execution of untrusted code requires a verified hardened isolation runtime such as Firecracker or gVisor.
- **Explainable decisions:** Findings, policy violations, scores, and verdicts should state why a decision was made.
- **Auditability:** Preserve enough metadata to understand prior decisions without retaining secrets unnecessarily.
- **Secret protection:** Redact secrets where possible and avoid raw-secret retention by default.
- **Human review remains required:** Automation helps prioritize risk; it does not replace secure engineering review.

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

### Build with Version Information

```bash
go build \
  -ldflags="-X main.Version=1.0.0 \
  -X main.Commit=$(git rev-parse --short HEAD) \
  -X main.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o bin/elevated-cli \
  ./cmd/elevated-cli
```

### Run Locally

```bash
go run ./cmd/elevated-cli --help
```

### Makefile

```bash
make build           # Build elevated-cli
make build-release   # Build with version, commit, and date metadata
make test            # Run tests with race detection
make gosec           # Run gosec
make vulncheck       # Run govulncheck
make all-checks      # Run formatting, vet, lint, tests, gosec, and vulncheck
```

---

## Testing Requirements

Before a release should be considered secure enough for broader internal testing, include tests for:

- Malformed AI responses
- Invalid JSON and Markdown code-block extraction
- Unsupported-language handling
- Invalid syntax
- Hardcoded-secret detection
- Dangerous import detection
- Shell and command-execution detection
- SQL-injection detection
- Dependency vulnerability reporting
- Missing scanner behavior
- Fail-closed policy behavior
- Blocking-policy behavior
- Safe external-command argument construction
- Path traversal prevention
- Temporary-directory containment
- Temporary-file cleanup
- Context timeout handling
- Process-tree cleanup
- Environment and secret isolation
- Network-denial enforcement (`block_network`) and fail-closed behavior when isolation is unavailable
- Score calculations
- Verdict precedence over scores
- Audit-log redaction
- SQLite database error handling
- CLI exit-code behavior
- End-to-end pipeline behavior
- Firecracker/gVisor backend failure handling when implemented
- Resource-limit and network-denial enforcement when implemented

---

## Roadmap

### P0 — Required Before Hostile-Code Execution

- [x] Cobra CLI and Viper configuration
- [x] LLM provider abstraction
- [x] Static analysis and dependency auditing integrations
- [x] Policy enforcement
- [x] Deterministic scoring
- [x] Structured reporting and SQLite history
- [x] Controlled local process execution with timeout and environment scrubbing
- [x] No silent fallback from requested microVM isolation to host `os/exec` (fail-closed now enforced)
- [x] Secret redaction and retention controls (`audit.store_prompts`, `store_generated_code`, `redact_secrets`; redaction on by default)
- [x] Enforced memory control (`prlimit --as` on Linux, fails closed) and network control (`unshare -U -n`, fails closed)
- [ ] Firecracker or gVisor hardened isolation
- [ ] Enforced CPU, process-count, output, and filesystem-control limits
- [ ] Hostile-code / sandbox-escape test coverage for a hardened runtime (process-runner hostile-code coverage: env scrubbing, containment, timeout, memory-limit — implemented)
- [ ] Independent security review of the execution backend
- [x] Correct exit codes for `BLOCKED`, `ANALYSIS_INCOMPLETE`, and `EXECUTION_FAILED`
- [x] Enforced `max_cyclomatic_complexity` policy rule (Go, via go/ast)

### P1 — Secure MVP Improvements

- [ ] Strong syntax validation for all supported languages
- [ ] More robust multi-language analyzers
- [ ] Explicit policy severity and action schema
- [ ] Policy file versioning
- [ ] Better remediation guidance
- [ ] Improved SARIF metadata
- [ ] CI gating based on verified exit-code behavior
- [ ] Test fixtures for vulnerable and malicious code
- [ ] Database retention controls
- [ ] Optional encrypted audit storage

### P2 — Production Hardening

- [ ] Firecracker microVM orchestration
- [ ] gVisor runtime support
- [ ] Hardened Docker/container profile, if adopted
- [ ] SBOM generation
- [ ] Signed binaries
- [ ] Reproducible builds
- [ ] Release provenance
- [ ] Dependency pinning and supply-chain verification
- [ ] Metrics and observability
- [ ] Policy bundles
- [ ] Plugin architecture
- [ ] Enterprise identity, access, and centralized audit export

> Until these P0 controls are implemented and independently tested, ElevateCLI is appropriate only for controlled local development and security-review workflows—not hostile-code execution or production security enforcement.

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

- New security controls include automated tests.
- Security-sensitive changes update the threat model.
- No secrets are committed.
- New policy rules document their behavior and severity.
- External tools are pinned and validated.
- Changes do not weaken fail-closed behavior.
- Sandbox changes receive careful security review.
- Documentation accurately distinguishes implemented, experimental, and planned functionality.

For major architecture or security changes, open an issue first to discuss design and threat-model impact.

---

## Responsible Disclosure

Do not open a public issue for a suspected security vulnerability.

Report security concerns privately to:

```text
security@your-domain.com
```

Include:

- A clear issue description
- Affected version or commit
- Reproduction steps
- Expected and actual behavior
- Potential impact
- Suggested remediation, if available

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Disclaimer

ElevateCLI is a security-assistance tool, not a security guarantee.

Automated analysis can miss vulnerabilities, produce false positives, depend on incomplete vulnerability databases, and be limited by the capabilities of the installed security tools and execution backend.

A positive score or `APPROVED` verdict means that the enabled controls found no blocking condition. It does not establish that code is safe, secure, production-ready, or safe to execute on the host.

Always use human code review, testing, least-privilege deployment, secure dependency management, hardened execution isolation, and appropriate operational security controls before deploying AI-generated code.
