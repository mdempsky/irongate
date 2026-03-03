# Build irongate binary.
FROM golang:1.26 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /irongate .

# Final image: opencode + irongate.
FROM ghcr.io/anomalyco/opencode:beta

COPY --from=builder /irongate /usr/local/bin/irongate

# HASH must be set at runtime: -e HASH=<sha256-hex-of-seed>
# API keys must also be set at runtime: -e ANTHROPIC_API_KEY=...

EXPOSE 443

# Reset the base image's ENTRYPOINT so our CMD runs directly.
ENTRYPOINT []

# irongate wraps opencode web server:
# - irongate listens on :443 with self-signed TLS
# - opencode listens on 127.0.0.1:4096 (only reachable through irongate)
# - irongate auto-sets OPENCODE_SERVER_PASSWORD for defense-in-depth
CMD ["irongate", \
     "-listen=:443", \
     "-tls=self-signed", \
     "-backend=127.0.0.1:4096", \
     "-prefix=/_ah/", \
     "--", \
     "opencode", "web", "--port", "4096", "--hostname", "127.0.0.1"]
