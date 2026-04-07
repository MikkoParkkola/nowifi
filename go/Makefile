VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build clean test all release-archives darwin-arm64 darwin-amd64 linux-arm64 linux-amd64

# Native build (CGO enabled on darwin → menubar included)
build:
	go build -ldflags "$(LDFLAGS)" -o bin/nowifi ./cmd/nowifi

# All cross-compile targets (CGO disabled → no menubar in cross-compiled binaries)
all: darwin-arm64 darwin-amd64 linux-arm64 linux-amd64

darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/nowifi-darwin-arm64 ./cmd/nowifi

darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/nowifi-darwin-amd64 ./cmd/nowifi

linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/nowifi-linux-arm64 ./cmd/nowifi

linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/nowifi-linux-amd64 ./cmd/nowifi

# Build all targets, package as tar.gz, generate sha256 checksums
release-archives: all
	cd bin && for f in nowifi-darwin-arm64 nowifi-darwin-amd64 nowifi-linux-amd64 nowifi-linux-arm64; do \
		tar czf "$$f.tar.gz" "$$f"; \
	done
	cd bin && shasum -a 256 *.tar.gz > checksums.sha256
	@echo "Release artifacts in go/bin/:"
	@ls -la bin/*.tar.gz bin/checksums.sha256

test:
	go test ./...

clean:
	rm -rf bin/
