#!/usr/bin/env bash
# Retire one frozen fips-base tag by overwriting it with the end-of-life
# marker image (eol/Dockerfile) on all three packages:
#
#   fips-base:<tag>              multi-arch marker, points at fips-base:latest
#   fips-base-linux-amd64:<tag>  amd64 marker, points at fips-base-linux-amd64:latest
#   fips-base-linux-arm64:<tag>  arm64 marker, points at fips-base-linux-arm64:latest
#
# Usage: eol/retire-fips-base-tag.sh <tag>        e.g. openssl3.0
#
# Requires `docker login ghcr.io` with a token that has write:packages.
# REGISTRY_REPO can be overridden to rehearse against a throwaway registry.
# See "Retiring a frozen tag" in FIPS.md.
set -euo pipefail

tag="${1:?usage: $0 <tag>}"
case "$tag" in
  openssl3|openssl3.0) ;;
  *) echo "refusing to retire '$tag': only the frozen openssl3 / openssl3.0 tags are retired this way" >&2; exit 2 ;;
esac

repo="${REGISTRY_REPO:-ghcr.io/aquia-inc/base-docker-images}"
pkg_url="https://github.com/aquia-inc/base-docker-images/pkgs/container/base-docker-images%2F"
docs_url="https://github.com/aquia-inc/base-docker-images/blob/main/FIPS.md#migrating-from-fips-base-to-fips-140-3"
reason="It was the retired FIPS 140-2 image. Its CMVP certificates (#4282, #4811) moved to the Historical list on 2026-09-21, and it no longer receives security fixes."
context="$(cd "$(dirname "$0")" && pwd)"

build_marker() {
  local platforms="$1" suffix="$2"
  docker buildx build --pull --push \
    --platform "$platforms" \
    --tag "${repo}/fips-base${suffix}:${tag}" \
    --build-arg RETIRED_REF="${repo}/fips-base${suffix}:${tag}" \
    --build-arg REPLACEMENT_REF="${repo}/fips-base${suffix}:latest" \
    --build-arg ALTERNATIVE_REF="${repo}/fips-140-3${suffix}:latest" \
    --build-arg PACKAGE_URL="${pkg_url}fips-140-3${suffix}" \
    --build-arg DOCS_URL="$docs_url" \
    --build-arg EOL_REASON="$reason" \
    "$context"
}

is_eol_marker() {
  docker buildx imagetools inspect "$1" --format '{{json .Image}}' 2>/dev/null |
    jq -e '[.. | objects | .Labels? // empty | .["org.aquia.base-docker-images.eol-marker"]?] | any(. == "true")' \
    > /dev/null 2>&1
}

build_marker "linux/amd64,linux/arm64" ""
build_marker "linux/amd64" "-linux-amd64"
build_marker "linux/arm64" "-linux-arm64"

failed=0
for suffix in "" "-linux-amd64" "-linux-arm64"; do
  ref="${repo}/fips-base${suffix}:${tag}"
  if is_eol_marker "$ref"; then
    echo "[ok] ${ref} is now the end-of-life marker"
  else
    echo "[fail] ${ref} is not the end-of-life marker" >&2
    failed=1
  fi
done
exit "$failed"
