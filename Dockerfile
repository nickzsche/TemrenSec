ARG TARGET=api

FROM golang:1.26-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /temren-api ./cmd/api && \
    CGO_ENABLED=0 GOOS=linux go build -o /temren-worker ./cmd/worker && \
    CGO_ENABLED=0 GOOS=linux go build -o /temren-cli ./cmd/temren

FROM alpine:3.19 AS api
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /temren-api /usr/local/bin/
COPY --from=builder /app/migrations ./migrations
EXPOSE 8080
CMD ["temren-api"]

FROM alpine:3.19 AS worker
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /temren-worker /usr/local/bin/
COPY --from=builder /app/migrations ./migrations
CMD ["temren-worker"]

FROM alpine:3.19 AS cli
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /temren-cli /usr/local/bin/
CMD ["temren", "--help"]
