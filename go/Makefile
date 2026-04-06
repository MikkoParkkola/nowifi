VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build clean test all darwin-arm64 darwin-amd64 linux-arm64 linux-amd64

build:
	go build -ldflags "$(LDFLAGS)" -o bin/nowifi ./cmd/nowifi

all: darwin-arm64 darwin-amd64 linux-arm64 linux-amd64

darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/nowifi-darwin-arm64 ./cmd/nowifi

darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/nowifi-darwin-amd64 ./cmd/nowifi

linux-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/nowifi-linux-arm64 ./cmd/nowifi

linux-amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/nowifi-linux-amd64 ./cmd/nowifi

test:
	go test ./...

clean:
	rm -rf bin/
