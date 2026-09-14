# Requires GNU make. On Windows use Git Bash / MSYS2 (`make` from the mingw
# toolchain) or WSL; the recipes below only rely on portable shell syntax.
SHELL := /bin/bash
GOCACHE ?= $(CURDIR)/.gocache
GOMODCACHE ?= $(CURDIR)/.gomodcache
export GOCACHE GOMODCACHE

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-s -w -X github.com/temren/cmd/temren/cmd.Version=$(VERSION)"
IMAGE_REPO ?= ghcr.io/nickzsche/temrensec

.PHONY: all build test bench lint vet tidy fmt cli api worker clean \
        docker docker-api docker-worker docker-cli docker-multiarch \
        cover frontend frontend-build frontend-lint frontend-typecheck frontend-test \
        helm-lint release release-snapshot security run dev compose-up compose-dev

all: lint test build

# ---- Go ----

build: cli api worker

cli:
	go build $(LDFLAGS) -o bin/temren ./cmd/temren

api:
	go build $(LDFLAGS) -o bin/temren-api ./cmd/api

worker:
	go build $(LDFLAGS) -o bin/temren-worker ./cmd/worker

test:
	go test -race -timeout=180s ./...

# Micro-benchmarks (see docs/PERFORMANCE.md). BENCH=<regex> narrows the set.
BENCH ?= .
bench:
	go test -run '^$$' -bench '$(BENCH)' -benchmem ./pkg/...

cover:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Open coverage.html"

vet:
	go vet ./...

fmt:
	gofmt -s -w .

tidy:
	go mod tidy

# golangci-lint v2 (config: .golangci.yml, version: "2")
lint:
	@command -v golangci-lint >/dev/null || (echo ">> Install golangci-lint v2: https://golangci-lint.run/welcome/install/" && exit 1)
	golangci-lint run ./...

security:
	@command -v gosec >/dev/null || (echo ">> Install gosec: go install github.com/securego/gosec/v2/cmd/gosec@latest" && exit 1)
	gosec -quiet ./...

# ---- Frontend ----

frontend:
	cd frontend && npm ci --prefer-offline --no-audit --no-fund

frontend-build:
	cd frontend && npm run build

frontend-lint:
	cd frontend && npm run lint

frontend-typecheck:
	cd frontend && npx tsc --noEmit

frontend-test:
	cd frontend && npm test --if-present

# ---- Containers ----

docker: docker-api docker-worker docker-cli

docker-api:
	docker build --target api -t $(IMAGE_REPO)-api:$(VERSION) --build-arg VERSION=$(VERSION) -f Dockerfile .

docker-worker:
	docker build --target worker -t $(IMAGE_REPO)-worker:$(VERSION) --build-arg VERSION=$(VERSION) -f Dockerfile .

docker-cli:
	docker build --target cli -t $(IMAGE_REPO)-cli:$(VERSION) --build-arg VERSION=$(VERSION) -f Dockerfile .

docker-multiarch:
	docker buildx build --platform=linux/amd64,linux/arm64 --target api -t $(IMAGE_REPO)-api:$(VERSION) --push .
	docker buildx build --platform=linux/amd64,linux/arm64 --target worker -t $(IMAGE_REPO)-worker:$(VERSION) --push .
	docker buildx build --platform=linux/amd64,linux/arm64 --target cli -t $(IMAGE_REPO)-cli:$(VERSION) --push .

compose-up:
	docker compose up -d --build

compose-dev:
	docker compose -f docker-compose.dev.yml up --build

helm-lint:
	helm lint helm/temren --set secrets.jwtSecret=lint --set postgresql.auth.password=lint

# ---- Release ----
# Releases are produced by goreleaser (.goreleaser.yaml); CI runs it on v* tags.
# `release-snapshot` builds every binary/archive locally into dist/ without publishing.

release-snapshot: clean
	@command -v goreleaser >/dev/null || (echo ">> Install goreleaser: go install github.com/goreleaser/goreleaser/v2@latest" && exit 1)
	goreleaser release --snapshot --clean

release: clean
	@command -v goreleaser >/dev/null || (echo ">> Install goreleaser: go install github.com/goreleaser/goreleaser/v2@latest" && exit 1)
	goreleaser release --clean

clean:
	rm -rf bin dist coverage.out coverage.html

# ---- Dev ----

dev:
	@command -v air >/dev/null || (echo ">> Install air: go install github.com/air-verse/air@latest"; exit 1)
	air

run: build
	./bin/temren-api
