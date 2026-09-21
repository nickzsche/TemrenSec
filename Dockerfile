# syntax=docker/dockerfile:1
#
# Multi-target build. Select the image with `--target api|worker|cli`
# (docker-compose and cd.yml do this); the builder cross-compiles on the
# build platform so linux/arm64 images don't need QEMU-emulated Go.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev

WORKDIR /app

RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -o /temren-api ./cmd/api && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -o /temren-worker ./cmd/worker && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
      -ldflags="-s -w -X github.com/temren/cmd/temren/cmd.Version=${VERSION}" -o /temren-cli ./cmd/temren

# ---------------------------------------------------------------- api
FROM alpine:3.20 AS api
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S temren && adduser -S temren -G temren
WORKDIR /app
COPY --from=builder /temren-api /usr/local/bin/temren-api
COPY --from=builder /app/migrations ./migrations
USER temren
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:${PORT:-8080}/health || exit 1
CMD ["temren-api"]

# ---------------------------------------------------------------- worker
FROM alpine:3.20 AS worker
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S temren && adduser -S temren -G temren
WORKDIR /app
COPY --from=builder /temren-worker /usr/local/bin/temren-worker
COPY --from=builder /app/migrations ./migrations
USER temren
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD pgrep temren-worker >/dev/null || exit 1
CMD ["temren-worker"]

# ---------------------------------------------------------------- cli
# Also used by the GitHub Action (action/action.yml -> docker://ghcr.io/nickzsche/temrensec-cli).
# entrypoint.sh runs a scan when the first argument is a URL and otherwise
# forwards all arguments to `temren`, so `docker run <image> export -f sarif ...` works too.
FROM alpine:3.20 AS cli
RUN apk add --no-cache ca-certificates tzdata jq
WORKDIR /work
COPY --from=builder /temren-cli /usr/local/bin/temren
COPY action/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD []
