#!/usr/bin/env bash
# launch.sh — Example script to build, launch, and enroll an irongate-protected
# opencode instance.
#
# Usage:
#   ./launch.sh [--host HOSTNAME] [--port PORT]
#
# Prerequisites:
#   - Docker installed and running
#   - An ANTHROPIC_API_KEY (or other LLM provider key) set in environment

set -euo pipefail

HOST="${1:-localhost}"
PORT="${2:-8443}"
IMAGE_NAME="irongate-opencode"

# Generate a random enrollment seed.
SEED=$(openssl rand -hex 32)
HASH=$(printf '%s' "$SEED" | shasum -a 256 | cut -d' ' -f1)

echo "=== Irongate Launch ==="
echo "Host:    $HOST"
echo "Port:    $PORT"
echo "Image:   $IMAGE_NAME"
echo ""
echo "Enrollment seed (keep secret): $SEED"
echo "Hash (stored in container):    $HASH"
echo ""

# Build the Docker image.
echo "Building Docker image..."
container build --no-cache -t "$IMAGE_NAME" .

# Determine the external origin for WebAuthn.
if [ "$PORT" = "443" ]; then
    ORIGIN="https://$HOST"
else
    ORIGIN="https://$HOST:$PORT"
fi

# Run the container.
echo "Starting container..."
CONTAINER_ID=$(container run -d \
    --name irongate-opencode-$$ \
    -p "$PORT":443 \
    -e HASH="$HASH" \
    -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}" \
    "$IMAGE_NAME" \
    irongate \
      -listen=:443 \
      -tls=self-signed \
      -backend=127.0.0.1:4096 \
      -prefix=/_ah/ \
      -origin="$ORIGIN" \
      -- \
      opencode web --port 4096 --hostname 127.0.0.1)

echo "Container: $CONTAINER_ID"

# Wait for the server to be ready.
echo "Waiting for server to be ready..."
for i in $(seq 1 30); do
    if curl -sk "https://$HOST:$PORT/_ah/health" >/dev/null 2>&1; then
        echo "Server is ready!"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: Server did not become ready in 30 seconds"
        echo "Check logs: container logs $CONTAINER_ID"
        exit 1
    fi
    sleep 1
done

# Build the enrollment URL.
ENROLL_URL="https://$HOST:$PORT/_ah/enroll#$SEED"
echo ""
echo "=== Enrollment URL ==="
echo "$ENROLL_URL"
echo ""
echo "Opening in browser..."

# Open the browser (macOS / Linux).
if command -v open &>/dev/null; then
    open "$ENROLL_URL"
elif command -v xdg-open &>/dev/null; then
    xdg-open "$ENROLL_URL"
else
    echo "(Could not detect browser opener. Please open the URL manually.)"
fi

echo ""
echo "=== Container Management ==="
echo "  Logs:  container logs -f $CONTAINER_ID"
echo "  Stop:  container stop $CONTAINER_ID"
echo "  Shell: container exec -it $CONTAINER_ID /bin/sh"
