#!/usr/bin/env bash
# Fail if a built image ships an apk package older than the repository offers.
#
# A vulnerability scanner can only report what its database knows, and ours
# has been blind to real content before: it did not index the Go toolchain,
# npm's bundled node_modules or virtualenv's seed wheels. An image can be
# genuinely stale while every gate here says clean. This asks a question that
# needs no CVE database: is anything installed older than the repository
# currently offers? "apk version -l <" answers it, and apk understands its own
# version grammar, including Wolfi's version-streamed names such as
# glibc-2.44, where a string or sort -V comparison picks the wrong winner.
#
# Self-healing: nothing is pinned and no package list is kept here. The image
# is compared with the live repository, and a package added later is covered
# the day it is added. It is NOT a vulnerability check - being current is not
# being free of vulnerabilities - only "we are not behind".
#
# The hard part is proving the comparison used the LIVE index. Measured on
# wolfi-base: with no network at all, "apk -U version" and "apk update" both
# exit 0, because the image carries the index from its own build, and
# "apk version" then reports everything current. So:
#   - an EMPTY cache directory is mounted over /var/cache/apk, hiding any index
#     baked into the image;
#   - "apk update" must succeed, print no warning, and leave a fresh APKINDEX
#     in that directory;
#   - "apk version" then runs with networking off against that index alone.
# Anything else is "freshness unknown", which fails.
#
# apk is run directly (no shell), as root because apk cannot write its index
# cache otherwise. apk is detected from the image's filesystem, so an image
# with no apk (nginx-base) says it had nothing to check, and one whose
# filesystem cannot be read fails.
#
# Usage: check-package-freshness.sh <image-ref> <platform>
set -euo pipefail

IMAGE="${1:?usage: check-package-freshness.sh <image-ref> <platform>}"
PLATFORM="${2:?usage: check-package-freshness.sh <image-ref> <platform>}"

echo "check-package-freshness: ${IMAGE} (${PLATFORM})"

list_files() {  # read from the filesystem; the container is created, never started
  local cid rc=0
  cid="$(docker create --platform "${PLATFORM}" "${IMAGE}" /guard-never-run)" || return 1
  docker export "${cid}" | tar -tf - || rc=1
  docker rm "${cid}" > /dev/null || true
  return "${rc}"
}

if ! files="$(set -o pipefail; list_files 2>&1)"; then
  echo "::error::check-package-freshness: could not read the image's filesystem; refusing to report clean" >&2
  printf '  %s\n' "${files//$'\n'/$'\n'  }" | tail -5 >&2
  exit 1
fi
if [ -z "${files}" ]; then
  echo "::error::check-package-freshness: the image's filesystem listing is empty; refusing to report clean" >&2
  exit 1
fi
if ! grep -qE '^(\./)?(s?bin|usr/s?bin)/apk$' <<< "${files}"; then
  echo "  no apk in this image - nothing to compare"
  exit 0
fi

cache="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/apk-cache.XXXXXX")"
apk_run() {
  docker run --rm --platform "${PLATFORM}" --user root \
    -v "${cache}:/var/cache/apk" --entrypoint apk "$@"
}

if ! update="$(apk_run "${IMAGE}" update 2>&1)"; then
  echo "::error::could not refresh the package index; freshness is UNKNOWN, not clean" >&2
  printf '  %s\n' "${update//$'\n'/$'\n'  }" >&2
  exit 1
fi
printf '  %s\n' "${update//$'\n'/$'\n'  }"
if grep -qiE 'WARNING|ERROR|unavailable' <<< "${update}"; then
  echo "::error::the package index refresh reported a problem; freshness is UNKNOWN, not clean" >&2
  exit 1
fi
if ! compgen -G "${cache}/APKINDEX.*.tar.gz" > /dev/null; then
  echo "::error::apk update left no fresh index; the comparison would use the image's own stale one" >&2
  exit 1
fi

# Networking off: the comparison may only use the index just fetched.
if ! report="$(apk_run --network none "${IMAGE}" version -l '<' 2>&1)"; then
  echo "::error::apk version failed; freshness is UNKNOWN, not clean" >&2
  printf '  %s\n' "${report//$'\n'/$'\n'  }" >&2
  exit 1
fi
if grep -qiE 'WARNING|ERROR' <<< "${report}"; then
  echo "::error::apk version reported a problem reading the index; freshness is UNKNOWN, not clean" >&2
  printf '  %s\n' "${report//$'\n'/$'\n'  }" >&2
  exit 1
fi

stale="$(sed '1{/^Installed:/d;}' <<< "${report}" | sed '/^[[:space:]]*$/d')"
if [ -z "${stale}" ]; then
  echo "check-package-freshness: ok - every installed package is the newest the repository offers"
  exit 0
fi

echo "::error::${IMAGE} ships packages older than the repository offers:" >&2
printf '%s\n' "${stale}" | sed 's/^/    /' >&2
echo "::error::a rebuild picks these up; if this persists, the image's apk upgrade step is not working." >&2
exit 1
