APP_NAME=elevated-cli
BINARY=./$(APP_NAME)
CMD_PATH=./cmd/elevated-cli/
BUILD_LDFLAGS=-s -w -X main.Version=1.0.0 -X main.Commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo none) -X main.Date=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: build run test lint clean install fmt vet cross

# Build single binary
build:
	go build -o $(APP_NAME) $(CMD_PATH)

# Build with version info
build-release:
	go build -ldflags="$(BUILD_LDFLAGS)" -o $(APP_NAME) $(CMD_PATH)

# Run directly without building
run:
	go run $(CMD_PATH) $(ARGS)

# Run tests
test:
	go test ./... -race -count=1 -v

# Run tests with coverage
test-coverage:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out

# Lint with golangci-lint (pinned; installed on demand so make lint works out of the box)
GOLANGCI_VERSION=v2.13.2
GOSEC_VERSION=v2.22.1

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION) run ./...

# Run gosec security scan on your own codebase
gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) ./...

# Check for vulnerabilities in dependencies
vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Format code
fmt:
	gofmt -w .

# Vet code
vet:
	go vet ./...

# Install binary to GOPATH/bin
install:
	go install $(CMD_PATH)

# Cross-compile for Linux (from macOS)
cross-linux:
	GOOS=linux GOARCH=amd64 go build -o $(APP_NAME)-linux $(CMD_PATH)

# Cross-compile for Windows
cross-windows:
	GOOS=windows GOARCH=amd64 go build -o $(APP_NAME).exe $(CMD_PATH)

# Cross-compile for macOS ARM (M1/M2)
cross-mac-arm:
	GOOS=darwin GOARCH=arm64 go build -o $(APP_NAME)-mac-arm $(CMD_PATH)

# Clean build artifacts
clean:
	rm -f $(APP_NAME) $(APP_NAME)-linux $(APP_NAME).exe $(APP_NAME)-mac-arm
	rm -f coverage.out

# Full check: fmt + vet + lint + test + gosec
all-checks: fmt vet lint test gosec vulncheck
	@echo "All checks passed."