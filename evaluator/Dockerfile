# Build stage: compile the static Go binary.
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Copy the entire monorepo so go.work and all local modules (core) are available
COPY . .

# Compile a fully static binary with no CGO dependencies.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.version=$(git describe --tags --always 2>/dev/null || echo dev)" \
    -o /evaluate \
    ./evaluator/cmd/evaluate/

# Production stage: empty scratch container.
# No shell, no OS, no attack surface.
FROM scratch

# Copy CA certificates so the binary can verify TLS connections.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the static binary from the build stage.
COPY --from=builder /evaluate /evaluate

USER 65532:65532

ENTRYPOINT ["/evaluate"]
CMD ["serve"]
