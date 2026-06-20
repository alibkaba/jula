# Build stage: compile the static Go binary.
FROM golang:1.25.10-alpine AS builder

WORKDIR /build

# Copy the entire monorepo so go.work and all local modules (core) are available
COPY . .

# Compile a fully static binary with no CGO dependencies.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.version=$(git describe --tags --always 2>/dev/null || echo dev)" \
    -o /collect \
    ./collector/cmd/collector/

# Production stage: distroless static container.
# No shell, no OS tools, no attack surface. Includes /tmp, CA certs, and nonroot user.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639

# Copy the static binary from the build stage.
COPY --from=builder /collect /collect

# Explicit non-root. The :nonroot tag defaults to 65532 but linters
# require a USER directive to verify.
USER 65532:65532

ENTRYPOINT ["/collect"]
CMD ["serve"]
