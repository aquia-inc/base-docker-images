#!/usr/bin/env bash
# Sign an image digest first, and only then point consumer tags at it.
#
# A tag applied before signing is visible and pullable while unsigned, and
# stays that way for good if signing then fails. Every path here therefore
# works on a digest that no consumer tag points at yet:
#
#   sign REF@DIGEST
#       Sign the digest and verify the signature. Fails unless it verifies.
#
#   verify REF@DIGEST
#       Fail unless the digest carries a signature from this repository.
#
#   tag-digest REF@DIGEST TAG_REF...
#       Point each TAG_REF (registry/repo:tag) at exactly that digest, then
#       check that every tag resolves to it.
#
#   publish-index DST_REPO TAG_REF... -- SRC@DIGEST...
#       Build a multi-arch index from per-architecture images under the
#       internal DST_REPO:unsigned-staging tag, sign it, then apply TAG_REFs.
#
#   mirror SRC@DIGEST DST_REPO TAG_REF...
#       Copy an image or index into another repository unchanged (same
#       digest), sign it there, then apply TAG_REFs.
#
# :unsigned-staging is the only tag ever pointed at an unsigned digest. No
# consumer is told to use it, and if signing fails it is all that moved.
#
# Signing is keyless (GitHub OIDC) in CI. Set COSIGN_KEY (and COSIGN_PUB) to
# sign and verify with a key pair instead, as the local tests do.
set -euo pipefail

STAGING_TAG="unsigned-staging"

die() { echo "::error::$*" >&2; exit 1; }

repo_of() {  # registry/repo@sha256:... or registry/repo:tag -> registry/repo
  local ref="${1%@*}"
  case "${ref##*/}" in *:*) ref="${ref%:*}" ;; esac
  printf '%s' "$ref"
}

digest_of() {  # the digest a reference resolves to, without rewriting anything
  docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' | jq -r '.digest'
}

# Extra cosign arguments, e.g. for a local plain-HTTP registry in tests.
read -ra SIGN_ARGS <<< "${COSIGN_SIGN_ARGS:-}"
read -ra VERIFY_ARGS <<< "${COSIGN_VERIFY_ARGS:-}"

verify() {
  local ref="$1"
  if [ -n "${COSIGN_PUB:-}" ]; then
    cosign verify --key "$COSIGN_PUB" "${VERIFY_ARGS[@]}" "$ref" > /dev/null
  else
    : "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is needed to verify a keyless signature}"
    cosign verify \
      --certificate-identity-regexp "^https://github.com/${GITHUB_REPOSITORY}/.github/workflows/" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      "${VERIFY_ARGS[@]}" "$ref" > /dev/null
  fi
}

cmd_sign() {
  local ref="$1"
  case "$ref" in *@sha256:*) ;; *) die "sign needs a digest reference, got $ref" ;; esac
  echo "Signing $ref"
  if [ -n "${COSIGN_KEY:-}" ]; then
    cosign sign --yes --key "$COSIGN_KEY" "${SIGN_ARGS[@]}" "$ref"
  else
    cosign sign --yes "${SIGN_ARGS[@]}" "$ref"
  fi
  verify "$ref" || die "signature on $ref does not verify; no tag will be applied"
  echo "[ok] signed and verified $ref"
}

cmd_tag_digest() {
  local src="$1"; shift
  case "$src" in *@sha256:*) ;; *) die "tag-digest needs a digest reference, got $src" ;; esac
  [ "$#" -gt 0 ] || die "tag-digest needs at least one tag"
  local want="${src##*@}" args=() t
  for t in "$@"; do args+=( --tag "$t" ); done
  # --prefer-index=false copies the source manifest as it is, so the tag points
  # at the signed digest itself rather than at a new index wrapping it.
  docker buildx imagetools create --prefer-index=false "${args[@]}" "$src"
  local failed=0 got
  for t in "$@"; do
    got="$(digest_of "$t")"
    if [ "$got" = "$want" ]; then
      echo "[ok] $t -> $want"
    else
      echo "::error::$t resolves to $got, expected the signed digest $want" >&2
      failed=1
    fi
  done
  return "$failed"
}

stage_and_resolve() {  # create DST:unsigned-staging from sources, print its digest
  local dst="$1"; shift
  docker buildx imagetools create "$@" --tag "${dst}:${STAGING_TAG}" >&2
  digest_of "${dst}:${STAGING_TAG}"
}

cmd_publish_index() {
  local dst="$1"; shift
  local tags=() sources=()
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do tags+=( "$1" ); shift; done
  [ "${1:-}" = "--" ] || die "publish-index: missing -- before the source images"
  shift
  sources=( "$@" )
  if [ "${#tags[@]}" -eq 0 ] || [ "${#sources[@]}" -eq 0 ]; then
    die "publish-index needs tags and sources"
  fi
  local digest
  digest="$(stage_and_resolve "$dst" "${sources[@]}")"
  if [ -z "$digest" ] || [ "$digest" = null ]; then
    die "could not resolve ${dst}:${STAGING_TAG}"
  fi
  cmd_sign "${dst}@${digest}"
  cmd_tag_digest "${dst}@${digest}" "${tags[@]}"
}

cmd_mirror() {
  local src="$1" dst="$2"; shift 2
  case "$src" in *@sha256:*) ;; *) die "mirror needs a digest source, got $src" ;; esac
  local digest
  digest="$(stage_and_resolve "$dst" --prefer-index=false "$src")"
  [ "$digest" = "${src##*@}" ] || die "mirror of $src into $dst changed the digest to $digest"
  cmd_sign "${dst}@${digest}"
  cmd_tag_digest "${dst}@${digest}" "$@"
}

main() {
  local cmd="${1:-}"; shift || true
  case "$cmd" in
    sign)          [ "$#" -eq 1 ] || die "usage: sign REF@DIGEST"; cmd_sign "$1" ;;
    verify)        [ "$#" -eq 1 ] || die "usage: verify REF@DIGEST"
                   verify "$1" || die "$1 is not signed by this repository"
                   echo "[ok] $1 verifies" ;;
    tag-digest)    cmd_tag_digest "$@" ;;
    publish-index) cmd_publish_index "$@" ;;
    mirror)        [ "$#" -ge 3 ] || die "usage: mirror SRC@DIGEST DST_REPO TAG_REF..."; cmd_mirror "$@" ;;
    repo-of)       repo_of "$1"; echo ;;
    *) sed -n '2,30p' "$0" >&2; exit 2 ;;
  esac
}

main "$@"
