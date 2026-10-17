APP_NAME=elevated-cli
BINARY=./$(APP_NAME)
CMD_PATH=./cmd/elevated-cli/

# Release metadata. VERSION defaults to 0.1.1; SOURCE_DATE_EPOCH defaults to the
# timestamp of HEAD so builds are reproducible, and the build date is derived
# from it rather than the wall clock.
VERSION ?= 0.1.1
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
BUILD_DATE ?= $(shell date -u -d @$(SOURCE_DATE_EPOCH) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
BUILD_LDFLAGS=-s -w -X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.Date=$(BUILD_DATE) -buildid=

.PHONY: build run test lint clean install fmt vet cross build-release

# Build single binary (reproducible: -trimpath strips host paths)
build:
	go build -trimpath -o $(APP_NAME) $(CMD_PATH)

# Build with version info (reproducible)
build-release:
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) go build -trimpath -ldflags="$(BUILD_LDFLAGS)" -o $(APP_NAME) $(CMD_PATH)

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

# Generate an SBOM for the built module
sbom:
	go run $(CMD_PATH) sbom --format cyclonedx --output - > sbom.cyclonedx.json

# Verify module checksums
verify:
	go mod verify

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
	GOOS=linux GOARCH=amd64 go build -trimpath -o $(APP_NAME)-linux $(CMD_PATH)

# Cross-compile for Windows
cross-windows:
	GOOS=windows GOARCH=amd64 go build -trimpath -o $(APP_NAME)-windows.exe $(CMD_PATH)

# Cross-compile for macOS
cross-darwin:
	GOOS=darwin GOARCH=arm64 go build -trimpath -o $(APP_NAME)-darwin $(CMD_PATH)

cross: cross-linux cross-windows cross-darwin

# Remove build artifacts
clean:
	rm -f $(APP_NAME) $(APP_NAME)-linux $(APP_NAME)-windows.exe $(APP_NAME)-darwin coverage.out sbom.cyclonedx.json
