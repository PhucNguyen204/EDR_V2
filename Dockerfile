# Multi-stage build
FROM golang:1.22 as builder
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -tags aho -o /out/edr-server ./cmd/edr-server

# Runtime image
FROM debian:stable-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY --from=builder /out/edr-server /usr/local/bin/edr-server
COPY --from=builder /app/migrations /srv/migrations
ENV EDR_ADDR=:8080
# Example DSN: postgres://user:pass@postgres:5432/edr?sslmode=disable
ENV EDR_DB_DSN=postgres://postgres:postgres@postgres:5432/edr?sslmode=disable
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/edr-server"]
