GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# Docker image names (override as needed): make docker IMAGE_REPO=ghcr.io/you/sbs
IMAGE_REPO ?= sbs
IMAGE_TAG  ?= $(VERSION)

# Release target: static binaries for these Linux architectures.
RELEASE_ARCHES ?= amd64 arm64
RELEASE_CMDS   ?= sbs-agent sbs-server sbs-bench

.PHONY: build test vet bench clean docker docker-server docker-agent compose-up compose-down release

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

# --- Docker images ---------------------------------------------------------
# Build both runtime targets from the one multi-stage Dockerfile.
docker: docker-server docker-agent

docker-server:
	docker build --target sbs-server --build-arg VERSION=$(VERSION) \
		-t $(IMAGE_REPO)-server:$(IMAGE_TAG) -t $(IMAGE_REPO)-server:latest .

docker-agent:
	docker build --target sbs-agent --build-arg VERSION=$(VERSION) \
		-t $(IMAGE_REPO)-agent:$(IMAGE_TAG) -t $(IMAGE_REPO)-agent:latest .

# --- Compose ---------------------------------------------------------------
compose-up:
	docker compose up -d --build

compose-down:
	docker compose down

# --- Release: static linux/amd64 + linux/arm64 tarballs into dist/ ---------
release:
	@rm -rf dist && mkdir -p dist
	@for arch in $(RELEASE_ARCHES); do \
		name=sbs-$(VERSION)-linux-$$arch; \
		out=dist/$$name; \
		mkdir -p $$out; \
		for cmd in $(RELEASE_CMDS); do \
			echo "building $$name/$$cmd"; \
			CGO_ENABLED=0 GOOS=linux GOARCH=$$arch \
				$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $$out/$$cmd ./cmd/$$cmd || exit 1; \
		done; \
		tar -C dist -czf dist/$$name.tar.gz $$name; \
	done
	@echo "release artifacts:"; ls -1 dist/*.tar.gz

clean:
	rm -rf bin reports dist
