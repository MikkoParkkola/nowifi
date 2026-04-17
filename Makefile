GOTOOLCHAIN ?= go1.26.2
GO ?= go
GO_RUN = GOTOOLCHAIN=$(GOTOOLCHAIN) $(GO)

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-s -w -X main.Version=$(VERSION)"

.PHONY: build install safe-clean clean force-clean

build:
	cd go && $(GO_RUN) build $(LDFLAGS) -o ../bin/nowifi ./cmd/nowifi

install:
	cd go && $(GO_RUN) build $(LDFLAGS) -o ~/.local/bin/nowifi ./cmd/nowifi

safe-clean: install
	rm -rf bin/

clean:
	@echo "WARNING: This removes ALL build artifacts including release binaries."
	@echo "Use 'make safe-clean' to install binaries first."
	@echo "Or 'make force-clean' to clean without installing."
	rm -rf bin/

force-clean:
	rm -rf bin/
