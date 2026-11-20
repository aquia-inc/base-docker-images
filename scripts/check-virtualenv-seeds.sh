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
#   2. virtualenv's declared inventory (RECORD and its SBOM) names no seed
#      wheel version that is not on disk, and the SBOM lists every seed wheel
#      on disk as a top-level component. The SBOM's metadata.tools and
#      formulation describe the toolchain that built virtualenv, not the
#      image, so they are the only parts left out
#   3. no seed wheel vendors a dependency older than the distro-patched
#      wheel of the same version in /usr/share/python-wheels - "not behind
#      the copy we trust", which picks up a future distro patch with no edit
#   4. function: a virtualenv created from the seed wheels runs pip
#
# An image with no seed wheels prints that it had nothing to check. An image
# whose filesystem cannot be read fails: a check that did not run must never
# read as a pass. Listing reads the filesystem without running anything, so
# images with no shell are covered too.
#
# Usage: check-virtualenv-seeds.sh <image-ref> <platform>
set -euo pipefail

IMAGE="${1:?usage: check-virtualenv-seeds.sh <image-ref> <platform>}"
PLATFORM="${2:?usage: check-virtualenv-seeds.sh <image-ref> <platform>}"

echo "check-virtualenv-seeds: ${IMAGE} (${PLATFORM})"

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
  echo "::error::check-virtualenv-seeds: could not read the image's filesystem; refusing to report clean" >&2
  printf '  %s\n' "${files//$'\n'/$'\n'  }" | tail -5 >&2
  exit 1
fi
if [ -z "${files}" ]; then
  echo "::error::check-virtualenv-seeds: the image's filesystem listing is empty; refusing to report clean" >&2
  exit 1
fi
wheels="$(printf '%s\n' "${files}" | grep -E '(^|/)virtualenv/seed/wheels/embed/[^/]+\.whl$' | sed 's|.*/||' | sort -u || true)"

if [ -z "${wheels}" ]; then
  echo "  no virtualenv seed wheels in this image - nothing to check"
  exit 0
fi

echo "  seed wheels found:"
printf '%s\n' "${wheels}" | sed 's/^/    /'

# Project names and versions from these file names are used in grep -E
# patterns below, so a name carrying anything but the characters a wheel file
# name uses ({name}-{version}[-{build}]-{python}-{abi}-{platform}.whl) is
# refused rather than interpreted as a pattern.
WHEEL_NAME='^[A-Za-z0-9_]+-[0-9][A-Za-z0-9_.!+]*(-[0-9][A-Za-z0-9_]*)?-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+\.whl$'
if printf '%s\n' "${wheels}" | grep -vqE "${WHEEL_NAME}"; then
  echo "::error::check-virtualenv-seeds: a seed wheel file name is not a plain wheel name; refusing to interpret it" >&2
  printf '%s\n' "${wheels}" | grep -vE "${WHEEL_NAME}" | sed 's/^/      /' >&2
  exit 1
fi

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
# Read with the image's python3, which any image carrying seed wheels has.
#
# The image's python3 runs isolated: -I ignores PYTHON* variables (the image
# sets PYTHONPATH) and keeps the working directory off sys.path, and -S skips
# site, so no module or .pth file in the image can stand in for json, glob, os
# or re. Its output is a line protocol the shell parses, so every value it
# prints is restricted to the characters a version uses; a crafted SBOM value
# cannot forge an SBOMS or TOP line.
if ! declared="$(docker run --rm --platform "${PLATFORM}" --workdir / --entrypoint python3 "${IMAGE}" -I -S -c '
import glob, json, os, re
PATTERN = re.compile(r"(?i)(?:pip|setuptools|wheel)-[0-9][^\"/,\s]*")
PURL = re.compile(r"(?i)pkg:pypi/(pip|setuptools|wheel)@([0-9][A-Za-z0-9._+!-]*)")
SAFE = re.compile(r"[a-z0-9][a-z0-9._+!-]*")
found = set()
top = set()
sboms = 0
def scan(text):
    for m in PATTERN.findall(text):
        # Text around a match (a ref suffix, a bracket) is cut at the first
        # character a version cannot contain.
        entry = re.sub(r"(-py[0-9].*|\.whl)$", "", m).lower()
        found.add(SAFE.match(entry).group(0))
# The same dist-info can be reached twice (the image links python3 to
# python3.13), so directories are de-duplicated by their real path.
dirs = sorted({os.path.realpath(d) for d in
               glob.glob("/usr/lib/python3*/site-packages/virtualenv-*.dist-info") +
               glob.glob("/home/*/.local/lib/python3*/site-packages/virtualenv-*.dist-info")})
for d in dirs:
    try:
        text = open(d + "/RECORD", encoding="utf8", errors="ignore").read()
    except OSError:
        text = ""
    scan(text)
    for f in sorted(glob.glob(d + "/sboms/*.json")):
        with open(f, encoding="utf8") as handle:
            document = json.load(handle)
        if not isinstance(document, dict):
            raise SystemExit("not an SBOM document: " + f)
        sboms += 1
        # Top-level components of the virtualenv CycloneDX SBOM are the
        # bundled seed wheels. Each is recorded twice: as a declared version,
        # and as TOP so the shell can require every wheel on disk to be among
        # them. A structured value is not trimmed: one that is not a plain
        # version is refused.
        for c in document.get("components") or []:
            if not isinstance(c, dict):
                continue
            name = str(c.get("name") or "").lower()
            if name in ("pip", "setuptools", "wheel") and c.get("version"):
                entry = name + "-" + str(c["version"]).lower()
                if SAFE.fullmatch(entry) is None:
                    raise SystemExit("unexpected characters in a seed wheel version: %r" % entry)
                found.add(entry)
                top.add(entry)
        # Everything else is still read as text, so a seed wheel named as a
        # wheel file or dist-info anywhere (nested, under metadata.component,
        # in a dependency reference) counts as declared. Only the toolchain
        # that built virtualenv is left out: metadata.tools and formulation
        # list hatchling, setuptools-scm and the setuptools they depend on,
        # none of which is in the image, and the dependency graph refers to
        # those tools by their bom-refs ("tool:pkg:pypi/..."), collected here.
        tool_refs = set()
        stack = [document.get("formulation")]
        if isinstance(document.get("metadata"), dict):
            stack.append(document["metadata"].get("tools"))
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                ref = node.get("bom-ref")
                if isinstance(ref, str) and ref.startswith("tool:"):
                    # In the form json.dumps writes it, which is the text
                    # it is compared against below.
                    tool_refs.add(json.dumps(ref)[1:-1])
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
        document.pop("formulation", None)
        if isinstance(document.get("metadata"), dict):
            document["metadata"].pop("tools", None)
        scan(json.dumps(document))
        # Seed wheels named as a purl (pkg:pypi/pip@26.0.1) count too, but
        # not the packages vendored INSIDE a seed wheel: those are the nested
        # entries and the "#vendored/pkg:..." suffix of a ref (PyPI pip
        # vendors a setuptools that is not a seed wheel). Nor the toolchain
        # refs: a build setuptools that differs from the bundled one is not a
        # seed. Each is removed only in its exact form - one purl ending the
        # string, or a whole string equal to a toolchain bom-ref - so a seed
        # ref written next to one is still read.
        for c in document.get("components") or []:
            if isinstance(c, dict):
                c.pop("components", None)
        text = re.sub(r"#vendored/pkg:[^\"\s#]*(?=\")", "", json.dumps(document))
        text = re.sub(r"\"(tool:(?:[^\"\\]|\\.)*)\"",
                      lambda m: "\"\"" if m.group(1) in tool_refs else m.group(0), text)
        for name, version in PURL.findall(text):
            entry = (name + "-" + version).lower()
            found.add(SAFE.match(entry).group(0))
print("\n".join(sorted(found)))
print("SBOMS %d" % sboms)
for entry in sorted(top):
    print("TOP " + entry)
' 2>&1)"; then
  echo "::error::check-virtualenv-seeds: could not read virtualenv's inventory; refusing to report clean" >&2
  printf '  %s\n' "${declared//$'\n'/$'\n'  }" >&2
  exit 1
fi
# Exactly one SBOMS line, and nothing else that starts like one: without it
# the read did not complete, and with two the count cannot be trusted.
if [ "$(printf '%s\n' "${declared}" | grep -c '^SBOMS' || true)" != "1" ] \
   || ! sbom_count="$(printf '%s\n' "${declared}" | grep -E '^SBOMS [0-9]+$')"; then
  echo "::error::check-virtualenv-seeds: the inventory read did not report exactly one SBOM count; refusing to report clean" >&2
  printf '  %s\n' "${declared//$'\n'/$'\n'  }" >&2
  exit 1
fi
sbom_count="${sbom_count#SBOMS }"
for project in ${projects}; do
  kept="$(printf '%s\n' "${wheels}" | grep -E "^${project}-[0-9]" | sed -E "s/^${project}-([^-]+)-.*$/\1/" | sort -V | tail -n1)"
  # The version is matched literally: "." and "+" in it are escaped. It must
  # end there: the next character may not continue a version, so kept 26.0
  # does not excuse 26.0.1, while 26.0.dist-info and 26.0-py3 still match.
  kept_re="$(printf '%s' "${kept}" | sed 's/[.+]/\\&/g')"
  bad="$(printf '%s\n' "${declared}" | grep -iE "^${project}-[0-9]" | grep -viE "^${project}-${kept_re}(\$|[^0-9.]|\.[^0-9])" || true)"
  if [ -n "${bad}" ]; then
    echo "::error::virtualenv's inventory still declares ${project} versions that are not on disk:" >&2
    printf '%s\n' "${bad}" | sed 's/^/      /' >&2
    violations=$((violations + 1))
  elif [ "${sbom_count}" -gt 0 ] && ! grep -qixF "TOP ${project}-${kept}" <<< "${declared}"; then
    # Without this, an SBOM whose layout moved the seed wheels out of the
    # top level would yield nothing to compare and read as agreement.
    echo "::error::virtualenv's SBOM does not list the ${project} ${kept} seed wheel on disk as a top-level component; its layout may have changed, so the inventory cannot be vouched for" >&2
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
    # The new environment must use its own seeded pip. An image can set
    # PYTHONPATH (python-base does), which would put the pip of the image
    # ahead of it, so the environment processes run without it, and the
    # pip that answers must live inside the environment.
    clean = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    run = subprocess.run([sys.executable, "-m", "virtualenv", "--no-periodic-update", "--quiet", env],
                         capture_output=True, text=True)
    pip = os.path.join(env, "bin", "pip")
    if run.returncode != 0 or not os.path.exists(pip):
        print("FUNCTION virtualenv could not create an environment: %s" % (run.stderr.strip()[-300:]))
        problems += 1
    else:
        out = subprocess.run([pip, "--version"], capture_output=True, text=True, env=clean)
        probe = subprocess.run([os.path.join(env, "bin", "python"), "-c",
                                "import pip._vendor.urllib3 as u, pip; print(u.__version__, pip.__file__)"],
                               capture_output=True, text=True, env=clean)
        seeded = os.path.realpath(env) + os.sep
        if out.returncode != 0 or probe.returncode != 0:
            print("FUNCTION pip in a new virtualenv failed: %s %s" % (out.stderr.strip()[-200:], probe.stderr.strip()[-200:]))
            problems += 1
        elif not os.path.realpath(probe.stdout.split()[-1]).startswith(seeded):
            print("FUNCTION the new virtualenv imported pip from %s, not its seeded copy" % probe.stdout.split()[-1])
            problems += 1
        else:
            print("WORKS new virtualenv: %s; its vendored urllib3 %s" % (out.stdout.strip(), probe.stdout.split()[0]))
print("DONE %d" % problems)
' 2>&1)" || {
  echo "::error::check-virtualenv-seeds: the in-image checks failed to run; refusing to report clean" >&2
  printf '  %s\n' "${result//$'\n'/$'\n'  }" >&2
  exit 1
}
printf '  %s\n' "${result//$'\n'/$'\n'  }"

if ! grep -qE '^DONE [0-9]+$' <<< "${result}" && ! grep -q '^NOSEEDS ' <<< "${result}"; then
  echo "::error::the in-image checks did not complete; refusing to report clean" >&2
  exit 1
fi
if grep -q '^NOSEEDS ' <<< "${result}"; then
  echo "::error::the shell found seed wheels but python3 did not; refusing to report clean" >&2
  exit 1
fi
if grep -q '^BEHIND ' <<< "${result}"; then
  echo "::error::a virtualenv seed wheel vendors a dependency older than the distro wheel of the same version. Every environment created from it inherits that code, and no scanner reads inside a .whl." >&2
  exit 1
fi
if ! grep -qE '^DONE 0$' <<< "${result}"; then
  echo "::error::check-virtualenv-seeds found problems (see above)" >&2
  exit 1
fi

echo "check-virtualenv-seeds: ok - one seed wheel per project, inventory agrees, interiors not behind the distro wheel, and a new virtualenv runs pip"
