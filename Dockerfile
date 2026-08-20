ARG TARGET=api

# Must track the toolchain in go.mod. This was pinned to 1.23 while go.mod
# declared 1.26, so every build depended on an implicit toolchain download.
FROM golang:1.26-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /temren-api ./cmd/api && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /temren-worker ./cmd/worker && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /temren-cli ./cmd/temren

# Nothing here needs root. A scanner that fetches attacker-controlled responses
# is exactly the kind of process that should not be uid 0 if it is ever
# compromised.
FROM alpine:3.19 AS api
RUN apk add --no-cache ca-certificates tzdata wget && \
    addgroup -g 10001 -S temren && \
    adduser -u 10001 -S temren -G temren
WORKDIR /app
COPY --from=builder /temren-api /usr/local/bin/
COPY --from=builder --chown=temren:temren /app/migrations ./migrations
USER temren:temren
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -q -O- http://127.0.0.1:8080/health || exit 1
CMD ["temren-api"]

FROM alpine:3.19 AS worker
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -g 10001 -S temren && \
    adduser -u 10001 -S temren -G temren
WORKDIR /app
COPY --from=builder /temren-worker /usr/local/bin/
COPY --from=builder --chown=temren:temren /app/migrations ./migrations
USER temren:temren
CMD ["temren-worker"]

FROM alpine:3.19 AS cli
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -g 10001 -S temren && \
    adduser -u 10001 -S temren -G temren
WORKDIR /app
COPY --from=builder /temren-cli /usr/local/bin/
USER temren:temren
CMD ["temren", "--help"]
