#!/bin/bash

# Function to increment patch version
increment_version() {
  local version=$1
  # Extract version number (remove release/image-name/v prefix)
  local ver_num=$(echo "$version" | sed 's/.*\/v//')
  # Split into major.minor.patch
  local major=$(echo "$ver_num" | cut -d. -f1)
  local minor=$(echo "$ver_num" | cut -d. -f2)
  local patch=$(echo "$ver_num" | cut -d. -f3)
  # Increment patch
  local new_patch=$((patch + 1))
  echo "$major.$minor.$new_patch"
}

echo "Current latest tags and proposed new versions:"
echo "=============================================="

# Fetch latest tags from origin
git fetch origin --tags >/dev/null 2>&1

# Get latest tag for each image type and calculate new version
for image in fips-base go-base nginx-base nodejs-base python-base wolfi-base openjdk17-base; do
  latest=$(git tag -l "release/$image/v*" | sort -V | tail -1)
  if [ -n "$latest" ]; then
    new_version=$(increment_version "$latest")
    new_tag="release/$image/v$new_version"
    echo "$image:"
    echo "  Current: $latest"
    echo "  New:     $new_tag"
    echo ""
  else
    echo "$image: No tags found"
    echo ""
  fi
done