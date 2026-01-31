# Python Hello World Example

A basic Python application demonstrating a 2-stage Docker build with Aquia's python-base image.

## What this shows

This example uses two stages: the first stage installs any dependencies using the full python-base image, and the second stage copies everything into a minimal runtime image. The result is a smaller, more secure container that only includes what's needed to run the app.

The app itself just prints a hello world message - nothing fancy. It's meant to show the build pattern, not be a real application.

## Files

- `app.py` - Simple Python script
- `requirements.txt` - Empty for now, but shows where dependencies would go
- `Dockerfile.example.python` - The 2-stage build configuration

The final image runs as a non-root user and uses Chainguard's minimal Python runtime.
