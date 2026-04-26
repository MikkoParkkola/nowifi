VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')
GO_VERSION := $(shell sed -n 's/^go //p' go.mod)
GO_RUN := GOTOOLCHAIN=go$(GO_VERSION) go
GO_TESTFLAGS ?=
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build clean test test-short test-coverage vet lint ci all release-archives darwin-arm64 darwin-amd64 linux-arm64 linux-amd64

# Native build (CGO enabled on darwin → menubar included)
build:
	$(GO_RUN) build -ldflags "$(LDFLAGS)" -o bin/nowifi ./cmd/nowifi

# All cross-compile targets (CGO disabled → no menubar in cross-compiled binaries)
all: darwin-arm64 darwin-amd64 linux-arm64 linux-amd64

darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO_RUN) build -ldflags "$(LDFLAGS)" -o bin/nowifi-darwin-arm64 ./cmd/nowifi

darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO_RUN) build -ldflags "$(LDFLAGS)" -o bin/nowifi-darwin-amd64 ./cmd/nowifi

linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO_RUN) build -ldflags "$(LDFLAGS)" -o bin/nowifi-linux-arm64 ./cmd/nowifi

linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO_RUN) build -ldflags "$(LDFLAGS)" -o bin/nowifi-linux-amd64 ./cmd/nowifi

# Build all targets, package as tar.gz, generate sha256 checksums
release-archives: all
	cd bin && for f in nowifi-darwin-arm64 nowifi-darwin-amd64 nowifi-linux-amd64 nowifi-linux-arm64; do \
		tar czf "$$f.tar.gz" "$$f"; \
	done
	cd bin && shasum -a 256 *.tar.gz > checksums.sha256
	@echo "Release artifacts in go/bin/:"
	@ls -la bin/*.tar.gz bin/checksums.sha256

test:
	$(GO_RUN) test $(GO_TESTFLAGS) ./...

test-short:
	$(GO_RUN) test -short $(GO_TESTFLAGS) ./...

test-coverage:
	$(GO_RUN) test -coverprofile=coverage.out ./...
	$(GO_RUN) tool cover -func=coverage.out

vet:
	$(GO_RUN) vet ./...

lint: vet
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not installed, skipping"; \
	fi
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed, skipping"; \
	fi

ci: build vet test

clean:
	rm -rf bin/
