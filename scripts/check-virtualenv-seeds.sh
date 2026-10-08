#!/usr/bin/env bash
# Fail if a built image carries a virtualenv seed wheel it should not.
#
# virtualenv bundles pip/setuptools wheels under virtualenv/seed/wheels/embed
# and seeds every environment it creates - including every poetry
# environment - from them. No scanner here reads inside a .whl, so a stale or
# vulnerable seed wheel ships while the image scans clean.
# harden-virtualenv-seeds.py fixes this at build time; this is the gate that
# stops a regression being published if that step is ever dropped, reordered
# or silently fails. It runs against the built test image, before any push.
#
# Four checks, each derived from the image itself rather than a list:
#   1. one seed wheel per project, and it is the highest version present
#   2. virtualenv's declared inventory (RECORD, CycloneDX SBOM) names no
#      seed wheel version that is not on disk
#   3. no seed wheel vendors a dependency older than the distro-patched
#      wheel of the same version in /usr/share/python-wheels - "not behind
#      the copy we trust", which picks up a future distro patch with no edit
#   4. function: a virtualenv created from the seed wheels runs pip
#
# An image with no seed wheels prints that it had nothing to check. An image
# that cannot be inspected at all fails: a check that did not run must never
# read as a pass.
#
# Usage: check-virtualenv-seeds.sh <image-ref> <platform>
set -euo pipefail

IMAGE="${1:?usage: check-virtualenv-seeds.sh <image-ref> <platform>}"
PLATFORM="${2:?usage: check-virtualenv-seeds.sh <image-ref> <platform>}"
SENTINEL="check-virtualenv-seeds-listing-complete"

echo "check-virtualenv-seeds: ${IMAGE} (${PLATFORM})"

in_image() {  # run a shell snippet in the image
  docker run --rm --platform "${PLATFORM}" --entrypoint sh "${IMAGE}" -c "$1"
}

# The sentinel proves the listing ran to the end, so an image that could not
# be started is a failure here, not an empty result.
listing="$(in_image "find / -xdev -path '*/virtualenv/seed/wheels/embed/*.whl' 2>/dev/null | sed 's|.*/||' | sort; echo ${SENTINEL}" 2>&1)" \
  && rc=0 || rc=$?
if [ "${rc}" -ne 0 ] || [ "${listing##*$'\n'}" != "${SENTINEL}" ]; then
  echo "::error::check-virtualenv-seeds: could not list the image's files (exit ${rc}); refusing to report clean" >&2
  printf '  %s\n' "${listing//$'\n'/$'\n'  }" >&2
  exit 1
fi
wheels="$(printf '%s\n' "${listing}" | grep -v "^${SENTINEL}\$" || true)"

if [ -z "${wheels}" ]; then
  echo "  no virtualenv seed wheels in this image - nothing to check"
  exit 0
fi

echo "  seed wheels found:"
printf '%s\n' "${wheels}" | sed 's/^/    /'

# 1. One version per project, the highest. sort -V ranks 26.10 above 26.2.
violations=0
projects="$(printf '%s\n' "${wheels}" | sed -E 's/^([A-Za-z0-9_.+]+)-[0-9].*$/\1/' | sort -u)"
for project in ${projects}; do
  versions="$(printf '%s\n' "${wheels}" | grep -E "^${project}-[0-9]" \
              | sed -E "s/^${project}-([^-]+)-.*$/\1/" | sort -V)"
  count="$(printf '%s\n' "${versions}" | grep -c . || true)"
  highest="$(printf '%s\n' "${versions}" | tail -n1)"
  if [ "${count}" -gt 1 ]; then
    echo "::error::${project} has ${count} seed wheels; only the highest (${highest}) may remain."
    printf '%s\n' "${versions}" | sed 's/^/      present: /'
    violations=$((violations + 1))
  else
    echo "  1. ${project}: ${highest} only - ok"
  fi
done

# 2. The declared inventory. Deleting the files but leaving the SBOM or RECORD
# naming them misreports the image, and is why such a finding has no path.
# Single quotes are deliberate: these expansions run inside the image.
# shellcheck disable=SC2016
declared="$(in_image '
  for d in $(find / -xdev -type d -name "virtualenv-*.dist-info" 2>/dev/null); do
    for f in "$d"/RECORD "$d"/sboms/*.json; do
      [ -f "$f" ] || continue
      grep -oE "(pip|setuptools|wheel)-[0-9][^\"/,[:space:]]*" "$f" 2>/dev/null
    done
  done | sed -E "s/(-py[0-9].*|\\.whl)$//" | sort -u' 2>/dev/null || true)"
for project in ${projects}; do
  kept="$(printf '%s\n' "${wheels}" | grep -E "^${project}-[0-9]" | sed -E "s/^${project}-([^-]+)-.*$/\1/" | sort -V | tail -n1)"
  bad="$(printf '%s\n' "${declared}" | grep -E "^${project}-[0-9]" | grep -vE "^${project}-${kept}([^0-9]|$)" || true)"
  if [ -n "${bad}" ]; then
    echo "::error::virtualenv's inventory still declares ${project} versions that are not on disk:" >&2
    printf '%s\n' "${bad}" | sed 's/^/      /' >&2
    violations=$((violations + 1))
  else
    echo "  2. ${project}: inventory agrees with disk - ok"
  fi
done
[ "${violations}" -eq 0 ] || exit 1

# 3 and 4 need the image's own Python, which every image with seed wheels has.
result="$(docker run --rm --platform "${PLATFORM}" --entrypoint python3 "${IMAGE}" -c '
import glob, os, re, site, subprocess, sys, tempfile, zipfile

def pins(zf, dist):
    """name -> version from <dist>/_vendor/vendor.txt inside a wheel."""
    out = {}
    for n in zf.namelist():
        if n.startswith(dist + "/") and n.endswith("_vendor/vendor.txt"):
            for raw in zf.read(n).decode("utf8", "ignore").splitlines():
                m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([^\s;,#]+)", raw.split("#", 1)[0].strip())
                if m:
                    out[re.sub(r"[-_.]+", "-", m.group(1)).lower()] = m.group(2)
    return out

def key(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])

# Real site-packages roots only: a recursive glob from / walks /proc and /sys.
roots = set(site.getsitepackages() or [])
try:
    roots.add(site.getusersitepackages())
except Exception:
    pass
roots.update(glob.glob("/usr/lib/python3*/site-packages"))
roots.update(glob.glob("/home/*/.local/lib/python3*/site-packages"))
seeds = sorted({os.path.realpath(w) for r in roots
                for w in glob.glob(r + "/virtualenv/seed/wheels/embed/*.whl")})
if not seeds:
    print("NOSEEDS python found no seed wheels under its site-packages")
    sys.exit(0)

problems = compared = 0
for seed in seeds:
    base = os.path.basename(seed)
    dist = base.split("-", 1)[0]
    refs = glob.glob("/usr/share/python-wheels/" + base)
    if not refs:
        print("NOREF %s: no distro wheel of the same version to compare against" % base)
        continue
    try:
        sp, rp = pins(zipfile.ZipFile(seed), dist), pins(zipfile.ZipFile(refs[0]), dist)
    except Exception as e:
        print("UNREADABLE %s: %s" % (base, e)); problems += 1; continue
    for name, sv in sorted(sp.items()):
        rv = rp.get(name)
        if rv is None:
            continue
        compared += 1
        if key(sv) < key(rv):
            print("BEHIND %s vendors %s %s; the distro wheel has %s" % (base, name, sv, rv)); problems += 1
print("COMPARED %d" % compared)

# 4. Function: create an environment from the seed wheels, offline, and run
# its pip, which imports the vendored code the checks above are about.
try:
    import virtualenv  # noqa: F401
except ImportError:
    print("NOVENV virtualenv is not importable; seed wheels cannot be exercised")
    problems += 1
else:
    env = tempfile.mkdtemp()
    run = subprocess.run([sys.executable, "-m", "virtualenv", "--no-periodic-update", "--quiet", env],
                         capture_output=True, text=True)
    pip = os.path.join(env, "bin", "pip")
    if run.returncode != 0 or not os.path.exists(pip):
        print("FUNCTION virtualenv could not create an environment: %s" % (run.stderr.strip()[-300:]))
        problems += 1
    else:
        out = subprocess.run([pip, "--version"], capture_output=True, text=True)
        probe = subprocess.run([os.path.join(env, "bin", "python"), "-c",
                                "import pip._vendor.urllib3 as u; print(u.__version__)"],
                               capture_output=True, text=True)
        if out.returncode != 0 or probe.returncode != 0:
            print("FUNCTION pip in a new virtualenv failed: %s %s" % (out.stderr.strip()[-200:], probe.stderr.strip()[-200:]))
            problems += 1
        else:
            print("WORKS new virtualenv: %s; its vendored urllib3 %s" % (out.stdout.strip(), probe.stdout.strip()))
print("DONE %d" % problems)
' 2>&1)" || {
  echo "::error::check-virtualenv-seeds: the in-image checks failed to run; refusing to report clean" >&2
  printf '  %s\n' "${result//$'\n'/$'\n'  }" >&2
  exit 1
}
printf '  %s\n' "${result//$'\n'/$'\n'  }"

if ! printf '%s\n' "${result}" | grep -qE '^DONE [0-9]+$' && ! printf '%s\n' "${result}" | grep -q '^NOSEEDS '; then
  echo "::error::the in-image checks did not complete; refusing to report clean" >&2
  exit 1
fi
if printf '%s\n' "${result}" | grep -q '^NOSEEDS '; then
  echo "::error::the shell found seed wheels but python3 did not; refusing to report clean" >&2
  exit 1
fi
if printf '%s\n' "${result}" | grep -q '^BEHIND '; then
  echo "::error::a virtualenv seed wheel vendors a dependency older than the distro wheel of the same version. Every environment created from it inherits that code, and no scanner reads inside a .whl." >&2
  exit 1
fi
if ! printf '%s\n' "${result}" | grep -qE '^DONE 0$'; then
  echo "::error::check-virtualenv-seeds found problems (see above)" >&2
  exit 1
fi

echo "check-virtualenv-seeds: ok - one seed wheel per project, inventory agrees, interiors not behind the distro wheel, and a new virtualenv runs pip"
