GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet bench clean

build:
	CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o bin/ ./cmd/...

test: vet
	$(GO) test ./...

vet:
	$(GO) vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

# Needs root (netlink process connector).
bench: build
	mkdir -p reports
	./bin/sbs-bench -json reports/bench.json -md reports/bench.md

clean:
	rm -rf bin reports
