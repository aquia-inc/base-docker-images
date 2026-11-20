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
# A package that is newer only in the live index - published after the build
# fetched its own - is a warning, not a failure, when the image's own index
# proves it (see below). Anything the build's own index offered and the
# image does not have still fails.
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
indexes=""
# Both temporary directories hold a full package index (megabytes each).
trap 'rm -rf "${cache}" ${indexes:+"${indexes}"}' EXIT
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

report_stale() {
  echo "::error::${IMAGE} ships packages older than the repository offers:" >&2
  printf '%s\n' "$1" | sed 's/^/    /' >&2
  echo "::error::a rebuild picks these up; if this persists, the image's apk upgrade step is not working." >&2
  exit 1
}
unknown() {
  echo "::error::$1; freshness is UNKNOWN, not clean" >&2
  report_stale "${stale}"
}

# Something is newer in the live index. Either the build had it and did not
# install it - the regression this guard exists for - or it reached the
# repository after the build fetched its index, which no build can avoid:
# fips-140-3 v0.0.61 failed on wolfi-keys 1-r15, which was not yet in the
# index its build fetched and was in the one this guard fetched minutes later.
# The image's own index tells the two apart. Every Dockerfile here runs
# "apk update" in the same step as its upgrade, busted per run by CACHEBUST,
# and leaves that index in /var/cache/apk; "apk version" against it, with
# networking off and no cache mounted, lists what the build could have
# installed and did not. A package stale against that index fails.
#
# A package stale only against the live index is a warning, not a failure,
# when the image's index is recent: the same repositories as the live one,
# and in EACH repository its newest package at most MAX_INDEX_LAG seconds
# older than the live index's newest. That bounds how far behind an image can
# be and still pass; it does not prove which index the build fetched. 1800 s
# is about twice the slowest whole publish run seen (14.2 min); an index the build
# failed to refresh, or an apk layer replayed from a build cache, is older
# and excuses nothing. Anything unreadable is UNKNOWN.
MAX_INDEX_LAG=1800

image_indexes="$(grep -oE '(^|/)var/cache/apk/APKINDEX\.[0-9a-f]+\.tar\.gz$' <<< "${files}" | sed 's|.*/||' | sort -u || true)"
if [ -z "${image_indexes}" ]; then
  unknown "the image keeps no package index from its own build, so a package published after the build cannot be told from one it failed to install"
fi
live_indexes="$(for f in "${cache}"/APKINDEX.*.tar.gz; do printf '%s\n' "${f##*/}"; done | sort -u)"
if [ "${image_indexes}" != "${live_indexes}" ]; then
  unknown "the image's own package index does not cover the same repositories as the live one (image: ${image_indexes//$'\n'/ }; live: ${live_indexes//$'\n'/ })"
fi

if ! build_report="$(docker run --rm --platform "${PLATFORM}" --user root --network none \
      --entrypoint apk "${IMAGE}" version -l '<' 2>&1)"; then
  unknown "apk version against the image's own index failed: ${build_report//$'\n'/ }"
fi
if grep -qiE 'WARNING|ERROR' <<< "${build_report}"; then
  unknown "apk could not read the image's own index cleanly: ${build_report//$'\n'/ }"
fi
build_stale="$(sed '1{/^Installed:/d;}' <<< "${build_report}" | sed '/^[[:space:]]*$/d' | awk '{print $1}')"

genuine=""
late=""
while IFS= read -r line; do
  [ -n "${line}" ] || continue
  if grep -qxF -- "${line%%[[:space:]]*}" <<< "${build_stale}"; then
    genuine="${genuine}${line}"$'\n'
  else
    late="${late}${line}"$'\n'
  fi
done <<< "${stale}"
if [ -n "${genuine}" ]; then
  report_stale "${genuine%$'\n'}"
fi

# Everything stale is newer only than the live index. Check the image's index
# is recent, repository by repository, by the newest package build time (t:)
# in each: one current repository must not vouch for a stale one.
indexes="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/apk-image-index.XXXXXX")"
cid="$(docker create --platform "${PLATFORM}" "${IMAGE}" /guard-never-run)" \
  || unknown "could not create a container to read the image's own index"
copied=0
docker cp "${cid}:/var/cache/apk/." "${indexes}/" > /dev/null 2>&1 || copied=1
docker rm "${cid}" > /dev/null 2>&1 || true
[ "${copied}" -eq 0 ] || unknown "could not copy the image's own package index out of it"

newest_build_time() {  # newest t: in one APKINDEX archive; fails on anything unreadable
  local t
  [ -f "$1" ] || return 1
  t="$(tar -xzOf "$1" APKINDEX | awk -F: '$1 == "t" && $2 + 0 > m { m = $2 + 0 } END { printf "%d\n", m }')" || return 1
  [ "${t}" -gt 0 ] || return 1
  printf '%s\n' "${t}"
}
widest=0
while IFS= read -r index; do
  image_newest="$(newest_build_time "${indexes}/${index}")" || image_newest=0
  live_newest="$(newest_build_time "${cache}/${index}")" || live_newest=0
  if [ "${image_newest}" -le 0 ] || [ "${live_newest}" -le 0 ]; then
    unknown "could not read package build times from ${index} (image: ${image_newest}, live: ${live_newest})"
  fi
  lag=$((live_newest - image_newest))
  if [ "${lag}" -lt 0 ]; then
    unknown "the image's own ${index} is newer than the live one (${lag} s), so the live index is not current"
  fi
  if [ "${lag}" -gt "${MAX_INDEX_LAG}" ]; then
    unknown "the image's own ${index} is ${lag} s behind the live one (limit ${MAX_INDEX_LAG} s), too old to excuse a package published since"
  fi
  [ "${lag}" -gt "${widest}" ] && widest="${lag}"
done <<< "${image_indexes}"

echo "::warning::${IMAGE}: published after this image's package index was fetched (at most ${widest} s between the two indexes); the next build picks these up:"
printf '%s' "${late}" | sed 's/^/    /'
echo "check-package-freshness: ok - nothing installed is older than the image's own package index; $(printf '%s' "${late}" | grep -c .) package(s) published since"
exit 0
