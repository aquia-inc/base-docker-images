#!/usr/bin/env bash
# Retire a stale tracking tag by pushing the end-of-life marker image
# (eol/Dockerfile) over it on all three packages of an image, so a consumer's
# build or `docker run` stops with the reason and the replacement instead of
# running an image that is never patched again:
#
#   <image>:<tag>              multi-arch marker, names <image>:latest
#   <image>-linux-amd64:<tag>  amd64 marker, names <image>-linux-amd64:latest
#   <image>-linux-arm64:<tag>  arm64 marker, names <image>-linux-arm64:latest
#
# The retention plan (scripts/ghcr-retention.py --retire-list) decides which
# tags; this script only carries one out.
#
# Usage: eol/retire-tag.sh <image> <tag> <digest> <amd64-digest> <arm64-digest>
#
# Each digest is where the plan saw the tag on that package ("-" when the plan
# did not see the tag there, which allows creating it but never overwriting
# it). A package whose tag now points anywhere else is refused rather than
# overwritten; one already holding the marker is a re-run and is skipped.
# Every push is verified by the marker's label afterwards.
#
# Requires `docker login ghcr.io` with a token that has write:packages, and a
# buildx builder that can build linux/arm64 (QEMU on an amd64 runner).
# REGISTRY_REPO can be overridden to rehearse against a throwaway registry.
set -euo pipefail

[ "$#" -eq 5 ] || { echo "usage: $0 <image> <tag> <digest> <amd64-digest> <arm64-digest>" >&2; exit 2; }
image="$1"; tag="$2"

# Never retire what the policy always keeps, and never build a reference from
# an unchecked string.
case "$tag" in
  latest|openssl3|openssl3.0|2|2.0|2.0.0)
    echo "refusing to retire '$image:$tag': the retention policy always keeps it" >&2; exit 2 ;;
esac
[[ "$image" =~ ^[a-z0-9][a-z0-9.-]{0,63}$ ]] || { echo "refusing: bad image name '$image'" >&2; exit 2; }
[[ "$tag" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$ ]] || { echo "refusing: bad tag '$tag'" >&2; exit 2; }
for digest in "$3" "$4" "$5"; do
  [[ "$digest" == "-" || "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "refusing: bad digest '$digest'" >&2; exit 2; }
done

repo="${REGISTRY_REPO:-ghcr.io/aquia-inc/base-docker-images}"
pkg_url="https://github.com/aquia-inc/base-docker-images/pkgs/container/base-docker-images%2F"
docs_url="https://github.com/aquia-inc/base-docker-images#image-retention"
reason="This tag stopped receiving updates when a newer version line shipped, and its last release has left the retention window."
context="$(cd "$(dirname "$0")" && pwd)"

digest_of() {
  docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' 2>/dev/null | jq -r '.digest // empty'
}

is_eol_marker() {
  docker buildx imagetools inspect "$1" --format '{{json .Image}}' 2>/dev/null |
    jq -e '[.. | objects | .Labels? // empty | .["org.aquia.base-docker-images.eol-marker"]?] | any(. == "true")' \
    > /dev/null 2>&1
}

# Whether a package needs the marker: 0 yes, 1 already done (a re-run), and a
# refusal (exit 2 from the subshell) when its tag is not where the plan saw it.
needs_marker() {
  local ref="$1" expected="$2" current want
  if is_eol_marker "$ref"; then
    echo "[ok] ${ref} is already the end-of-life marker"
    return 1
  fi
  current="$(digest_of "$ref")"
  # "-": the plan did not see this tag on this package, so it may only be
  # created there, never overwritten.
  want="$expected"
  if [ "$want" = "-" ]; then
    want=""
  fi
  if [ "$current" != "$want" ]; then
    echo "[fail] refusing to retire ${ref}: it points at ${current:-nothing}, the plan saw ${expected}" >&2
    return 2
  fi
  return 0
}

build_marker() {
  local platforms="$1" suffix="$2" ref="${repo}/${image}${2}:${tag}"
  docker buildx build --pull --push \
    --platform "$platforms" \
    --provenance=false --sbom=false \
    --tag "$ref" \
    --build-arg RETIRED_REF="$ref" \
    --build-arg REPLACEMENT_REF="${repo}/${image}${suffix}:latest" \
    --build-arg PACKAGE_URL="${pkg_url}${image}${suffix}" \
    --build-arg DOCS_URL="$docs_url" \
    --build-arg EOL_REASON="$reason" \
    "$context"
  if is_eol_marker "$ref"; then
    echo "[ok] ${ref} is now the end-of-life marker"
  else
    echo "[fail] ${ref} is not the end-of-life marker after the push" >&2
    return 1
  fi
}

# Check all three packages before pushing anything, so a refusal leaves the
# image untouched rather than retired on some packages and not others.
suffixes=("" "-linux-amd64" "-linux-arm64")
platforms=("linux/amd64,linux/arm64" "linux/amd64" "linux/arm64")
expected=("$3" "$4" "$5")
todo=()
for i in 0 1 2; do
  status=0
  needs_marker "${repo}/${image}${suffixes[$i]}:${tag}" "${expected[$i]}" || status=$?
  case "$status" in
    0) todo+=("$i") ;;
    1) ;;
    *) exit 1 ;;
  esac
done

for i in ${todo[@]+"${todo[@]}"}; do
  build_marker "${platforms[$i]}" "${suffixes[$i]}"
done
