#!/bin/bash

set -e

# Enable binfmt_misc for emulation
echo "Setting up emulation..."
docker run --privileged --rm tonistiigi/binfmt --install all

# Build the Docker image
echo "Building Docker image..."
docker buildx create --use
docker buildx build --pull --platform linux/amd64 -t nginx-fips-test -f Dockerfile.nginx-fips . --load

# Run a container from the image
echo "Running container..."
container_id=$(docker run --platform linux/amd64 -d -p 8080:80 nginx-fips-test)

# Wait for the container to start
echo "Waiting for container to start..."
sleep 10  # Increased wait time due to emulation

# Check if NGINX is running
echo "Checking if NGINX is running..."
if docker exec $container_id pgrep nginx > /dev/null; then
    echo "NGINX is running."
else
    echo "NGINX is not running."
    docker logs $container_id
    docker stop $container_id
    exit 1
fi

# Check if NGINX is serving requests
echo "Checking if NGINX is serving requests..."
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080)
if [ $response = "200" ]; then
    echo "NGINX is serving requests successfully."
else
    echo "NGINX is not serving requests. HTTP status code: $response"
    docker logs $container_id
    docker stop $container_id
    exit 1
fi

# Check FIPS mode
echo "Checking FIPS mode..."
if docker exec $container_id openssl md5 /etc/hosts | grep -q "disabled for fips"; then
    echo "FIPS mode is enabled."
else
    echo "FIPS mode is not enabled."
    docker stop $container_id
    exit 1
fi

# Clean up
echo "Cleaning up..."
docker stop $container_id
docker rm $container_id

echo "Smoke test completed successfully!"