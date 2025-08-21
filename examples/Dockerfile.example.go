# Example: Using Aquia Go Base Image
# This demonstrates how to use our pre-built, hardened Go base image.
# Our go-base image provides the Go toolchain for building your applications.

# Build stage: Use our Go base image pinned to Go 1.25
# NOTE: Replace :latest with current version tag from https://github.com/aquia-inc/base-docker-images/releases
FROM ghcr.io/aquia-inc/base-docker-images/go-base-linux-amd64:latest AS builder

USER nonroot
WORKDIR /workspace

# Show Go version information from our base image
RUN echo "=== Aquia Go Base Image ===" && \
    cat /tmp/versions.txt && \
    echo "=== Go Build Environment ===" && \
    go version

# Copy Go module files and download dependencies
COPY --chown=nonroot:nonroot go-app/go.mod go-app/go.sum* ./
RUN go mod download

# Copy application source and build
COPY --chown=nonroot:nonroot go-app/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o hello-world .

# Runtime stage: Use a minimal static base for deployment
FROM cgr.dev/chainguard/static:latest@sha256:6a4b683f4708f1f167ba218e31fcac0b7515d94c33c3acf223c36d5c6acd3783

# Copy the compiled binary from builder stage
COPY --from=builder /workspace/hello-world /hello-world

# Run as nonroot user for security
USER nonroot

# Set the entrypoint to your application
ENTRYPOINT ["/hello-world"]
