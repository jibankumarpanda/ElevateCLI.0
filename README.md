Made for devlopers. for the active function, Cli
# ElevatedCLI (`elevated-cli`)

[![Go Version](https://img.shields.io/badge/go-1.22%2B-blue.svg)](https://golang.org)
[![Security Scale](https://img.shields.io/badge/security-0--100-green.svg)](#security-scoring)

`elevated-cli` is a production-grade, security-first command-line tool designed for developers who want to leverage AI code generation without introducing vulnerabilities. Every piece of code generated is passed through a multi-stage security verification pipeline.

---

##  Key Features

*   **Multi-Model Support**: Connects to OpenAI (GPT-4o), Anthropic, or local Ollama models.
*   **4-Stage Verification Pipeline**:
    1.  **SAST (Static Analysis)**: Runs `gosec` to detect deep security flaws like SQL injection or hardcoded credentials.
    2.  **Dependency Auditing**: Uses `osv-scanner` to check generated manifests against global CVE databases.
    3.  **Policy Enforcement**: Custom AST-based engine to block unsafe imports (e.g., `unsafe`, `syscall`) and functions.
    4.  **Sandbox Execution**: Executes code in isolated environments (Linux Namespaces or Firecracker MicroVMs).
*   **Security Scoring**: A weighted 0–100 score determines if code is **Approved**, **Warning**, or **Rejected**.
*   **Audit Database**: All prompts, generated code, and security findings are logged locally in a pure-Go SQLite database.

---

##  Tech Stack

- **Core**: Go 1.22+
- **CLI Framework**: Cobra & Viper
- **AI Integration**: OpenAI SDK & Ollama API
- **Security Tools**: `gosec`, `osv-scanner`
- **Sandbox**: Linux Namespaces, `firecracker-go-sdk`
- **Terminal UI**: Bubble Tea & Lip Gloss
- **Database**: `modernc.org/sqlite` (No CGO)

---

##  Installation

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/jibankumarpanda/ElevateCLI.0.git
    cd ElevateCLI.0
    ```

2.  **Install Dependencies**:
    ```bash
    go mod tidy
    ```

3.  **Install External Security Tools**:
    ```bash
    # Install gosec
    go install github.com/securego/gosec/v2/cmd/gosec@latest
    # Install osv-scanner
    go install github.com/google/osv-scanner/cmd/osv-scanner@latest
    ```

---

##  Configuration

Create a `.elevated-cli.yaml` in your project root or home directory:

```yaml
ai:
  provider: openai
  model: gpt-4o
  api_key: "your-api-key"

sandbox:
  mode: process # process or firecracker

policy:
  rules:
    blocked_imports: [os/exec, syscall, unsafe]
    blocked_functions: [eval, exec, system]
    require_error_handling: true
```

---

##  Usage

### Generate Code
Generate code from a natural language prompt and run it through the security pipeline:
```bash
go run cmd/elevated-cli/main.go generate --prompt "Create a Go function to read a file securely" --lang go --run
```

### Audit Existing Code
```bash
go run cmd/elevated-cli/main.go audit --file path/to/file.go
```

### View History
```bash
go run cmd/elevated-cli/main.go history --last 5
```

---

## 🛡 Security Scoring

The final score (0–100) is calculated as follows:
*   **SAST (40%)**: Deductions for critical/high/medium findings.
*   **Dependencies (30%)**: Deductions for known CVEs.
*   **Policy (20%)**: Deductions for prohibited imports or functions.
*   **Sandbox (10%)**: Deductions for runtime errors or suspicious behavior.

**Verdict Thresholds:**
-  **APPROVED** (70+): Safe to integrate.
-  **WARNING** (40–69): Review findings before use.
-  **REJECTED** (<40): Do not use; critical security risks.

---

##  License
MIT License. See `LICENSE` for details.
