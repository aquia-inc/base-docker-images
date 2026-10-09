#!/usr/bin/env bash
# Fail if a built image's pip vendored tree is behind its fix, or misdeclared.
#
# pip ships its dependencies vendored under pip/_vendor and declares them in
# vendor.txt and a CycloneDX bom.cdx.json. Scanners read those declarations as
# the inventory, so a stale one is reported as a vulnerability that is not there
# - or hides one that is - and the finding carries no file path. Measured on
# pip 26.2.1: the BOM declared urllib3 2.7.0 against 2.8.0 on disk, and idna
# 3.18 against 3.15.
#
# harden-pip-vendor.py fixes the vendored tree and reconciles both declarations
# at build time. This is the gate that stops a regression being published if
# that step is dropped, reordered or silently fails.
#
# The expectations are the fix script's own, not a second list: the script is
# mounted read-only into the image and its own functions are run against every
# pip tree on disk -
#   - verify_declarations: vendor.txt and bom.cdx.json both agree with the
#     version read from the vendored code itself
#   - the msgpack floor (MSGPACK_MIN) holds for the vendored copy
#   - verify: function - the fixed msgpack imports, pip's cachecontrol
#     serializer and metadata backend work, and pkg_resources is gone
#
# An image with no pip vendored tree says it had nothing to check. An image
# whose filesystem cannot be read fails. Detection reads the filesystem
# without running anything, so images with no shell are covered too.
#
# Usage: check-pip-vendor-bom.sh <image-ref> <platform>
set -euo pipefail

IMAGE="${1:?usage: check-pip-vendor-bom.sh <image-ref> <platform>}"
PLATFORM="${2:?usage: check-pip-vendor-bom.sh <image-ref> <platform>}"
FIX="$(cd "$(dirname "$0")" && pwd)/harden-pip-vendor.py"

echo "check-pip-vendor-bom: ${IMAGE} (${PLATFORM})"
[ -f "${FIX}" ] || { echo "::error::fix script not found at ${FIX}" >&2; exit 1; }

# The image's file list, read from its filesystem rather than by running a
# command in it, so an image with no shell (nginx-base) is listed like any
# other. The container is created, never started.
list_files() {
  local cid rc=0
  cid="$(docker create --platform "${PLATFORM}" "${IMAGE}" /guard-never-run)" || return 1
  docker export "${cid}" | tar -tf - || rc=1
  docker rm "${cid}" > /dev/null || true
  return "${rc}"
}

# A listing that failed is a failure, never an empty result.
if ! files="$(set -o pipefail; list_files 2>&1)"; then
  echo "::error::check-pip-vendor-bom: could not read the image's filesystem; refusing to report clean" >&2
  printf '  %s\n' "${files//$'\n'/$'\n'  }" | tail -5 >&2
  exit 1
fi
if [ -z "${files}" ]; then
  echo "::error::check-pip-vendor-bom: the image's filesystem listing is empty; refusing to report clean" >&2
  exit 1
fi
if ! grep -qE '(^|/)site-packages/pip/_vendor/vendor\.txt$' <<< "${files}"; then
  echo "  no pip vendored tree in this image - nothing to check"
  exit 0
fi
if ! grep -qE '(^|/)bin/python3$' <<< "${files}"; then
  echo "::error::check-pip-vendor-bom: the image has a pip vendored tree but no python3 to inspect it with; refusing to report clean" >&2
  exit 1
fi

result="$(docker run --rm --platform "${PLATFORM}" \
  -v "${FIX}:/opt/guard/harden_pip_vendor.py:ro" \
  --entrypoint python3 "${IMAGE}" -c '
import glob, os, subprocess, sys

# Real site-packages roots only; a recursive glob from / walks /proc and /sys.
roots = sorted({os.path.realpath(p) for pattern in (
        "/usr/lib/python3*/site-packages", "/usr/local/lib/python3*/site-packages",
        "/home/*/.local/lib/python3*/site-packages", "/root/.local/lib/python3*/site-packages")
    for p in glob.glob(pattern) if os.path.isdir(os.path.join(p, "pip", "_vendor"))})
if not roots:
    print("SKIP python is present but no pip vendored tree is installed")
    sys.exit(0)

# Each tree is checked in its own interpreter with that tree first on the path,
# so the fix script (which imports pip) inspects this tree and not another one.
driver = r"""
import importlib.util, os, sys
root = sys.argv[1]
spec = importlib.util.spec_from_file_location("fix", "/opt/guard/harden_pip_vendor.py")
fix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fix)
import pip
if not os.path.realpath(pip.__file__).startswith(root + os.sep):
    print("PROBLEM imported pip from %s, not the tree under %s" % (pip.__file__, root)); sys.exit(0)
vendor = fix.find_vendor_dir()
print("TREE %s (pip %s)" % (vendor, pip.__version__))
problems = 0
def step(label, fn):
    global problems
    try:
        fn()
        print("OK %s" % label)
    except SystemExit as e:
        print("PROBLEM %s: %s" % (label, e)); problems += 1
step("declarations agree with the vendored code", lambda: fix.verify_declarations(vendor))
msgpack = fix.code_version(vendor, "msgpack")
def floor():
    if msgpack is None or fix.normalize_version(msgpack) < tuple(fix.MSGPACK_MIN):
        fix.fail("vendored msgpack %s is below %s" % (msgpack, ".".join(map(str, fix.MSGPACK_MIN))))
step("vendored msgpack %s meets the fix floor" % msgpack, floor)
step("function: pip runs with the fixed vendored code", lambda: fix.verify(vendor, msgpack or "?"))
print("TREEDONE %d" % problems)
"""
total = 0
for root in roots:
    env = dict(os.environ, PYTHONPATH=root)
    run = subprocess.run([sys.executable, "-c", driver, root], capture_output=True, text=True, env=env)
    out = (run.stdout + run.stderr).strip()
    print(out)
    if run.returncode != 0 or "TREEDONE 0" not in out:
        total += 1
print("DONE %d" % total)
' 2>&1)" || {
  echo "::error::check-pip-vendor-bom: the in-image checks failed to run; refusing to report clean" >&2
  printf '  %s\n' "${result//$'\n'/$'\n'  }" >&2
  exit 1
}
printf '  %s\n' "${result//$'\n'/$'\n'  }"

if grep -q '^SKIP ' <<< "${result}"; then
  exit 0
fi
if ! grep -qE '^DONE [0-9]+$' <<< "${result}"; then
  echo "::error::check-pip-vendor-bom: the checks did not complete; refusing to report clean" >&2
  exit 1
fi
if ! grep -qx 'DONE 0' <<< "${result}"; then
  echo "::error::pip's vendored tree is behind harden-pip-vendor.py's fix, or its declarations disagree with the code. Scanners read those declarations as the image's inventory." >&2
  exit 1
fi

echo "check-pip-vendor-bom: ok - every pip tree matches its declarations, meets the fix floor, and works"
