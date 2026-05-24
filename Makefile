BINARY      := licscan
PKG         := github.com/codelake-dev/licscan
CMD         := ./cmd/licscan
BIN_DIR     := ./bin
INSTALL_DIR := $(shell go env GOPATH)/bin

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
  -X $(PKG)/internal/version.Version=$(VERSION) \
  -X $(PKG)/internal/version.Commit=$(COMMIT) \
  -X $(PKG)/internal/version.BuildDate=$(BUILD_DATE)

.PHONY: all
all: lint test build

.PHONY: build
build:
	mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) $(CMD)

.PHONY: install
install:
	go install -trimpath -ldflags '$(LDFLAGS)' $(CMD)

.PHONY: test
test:
	go test ./... -race -count=1

.PHONY: cover
cover:
	go test ./... -race -coverprofile=coverage.out -covermode=atomic
	go tool cover -func=coverage.out | tail -1
	@echo "HTML report: go tool cover -html=coverage.out -o coverage.html"

.PHONY: lint
lint:
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed: https://golangci-lint.run/usage/install/"; exit 1)
	golangci-lint run ./...

.PHONY: fmt
fmt:
	gofmt -s -w .

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) coverage.out coverage.html dist/

.PHONY: release-dry-run
release-dry-run:
	@which goreleaser > /dev/null || (echo "goreleaser not installed: https://goreleaser.com/install/"; exit 1)
	goreleaser release --snapshot --clean --skip=publish

.PHONY: help
help:
	@echo "Targets:"
	@echo "  build              Build the binary into $(BIN_DIR)/$(BINARY)"
	@echo "  install            go install into $(INSTALL_DIR)"
	@echo "  test               Run tests with race detector"
	@echo "  cover              Run tests with coverage report"
	@echo "  lint               Run golangci-lint"
	@echo "  fmt                Format all Go source"
	@echo "  tidy               go mod tidy"
	@echo "  clean              Remove build artefacts"
	@echo "  release-dry-run    Local goreleaser dry-run (no publish)"
