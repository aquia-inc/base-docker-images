# Examples Directory

This directory contains simple example Dockerfiles and configurations that demonstrate how to use Aquia's hardened base Docker images in real-world applications.

## ⚠️ Important Notice

**These examples are for demonstration purposes only.** The version tags in these Dockerfiles use `:latest` as placeholders and are NOT kept up-to-date. They may reference outdated images with security vulnerabilities.

**For production use, always replace `:latest` with current version tags from the [officially published images](https://github.com/orgs/aquia-inc/packages?repo_name=base-docker-images).**

## Available Examples

### 🐹 Go Application (`Dockerfile.example.go`)

- **Purpose**: Demonstrates building a Go application using our `go-base` image
- **Architecture**: Multi-stage build (build → minimal static runtime)
- **Features**: 
  - Uses hardened Go base image for compilation
  - Outputs to Chainguard's static image for minimal attack surface
  - Proper non-root user handling
  - Displays version information from base image

### 🌐 Nginx + Node.js Application (`Dockerfile.example.nginx`)

- **Purpose**: Shows how to build a frontend application and serve it with Nginx
- **Architecture**: Multi-stage build (Node.js build → Nginx runtime)
- **Features**:
  - Uses `nodejs-base` for building frontend assets
  - Uses `nginx-base` for serving static files
  - Custom Nginx configuration included
  - Security-focused configuration

### 📄 Supporting Files

- **`default.conf`**: Example Nginx configuration with security hardening
- **`go-app/`**: Simple "Hello World" Go application with module definition  
- **`frontend-app/`**: Minimalist Node.js frontend app 

## Usage

To use these examples as starting points:

1. **Copy the relevant Dockerfile** to your project
2. **Replace `:latest` tags** with current version tags from [GHCR packages](https://github.com/orgs/aquia-inc/packages?repo_name=base-docker-images)
3. **Modify** the example to fit your application's specific needs
4. **Test locally** before deploying to any higher enviuronments.  Be thorough in your testing/validation.

## Getting Current Image References

For the most up-to-date image references, see:
- [Latest Releases](https://github.com/aquia-inc/base-docker-images/releases)
- [GHCR Package Registry](https://github.com/orgs/aquia-inc/packages?repo_name=base-docker-images)
- Repository README for current version information

## Best Practices

When adapting these examples:
- Always use SHA pinning for reproducible builds
- Add the `--pull` flag to your `docker build` commands
- Run container structure tests before deployment
- Follow the principle of least privilege (non-root users)
- Use multi-stage builds to minimize final image size