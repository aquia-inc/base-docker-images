"""Tests for scripts/check-package-freshness.sh, run against a docker stand-in.

Hermetic: a fake "docker" on PATH serves an image file listing, the image's
own build-time APKINDEX, a live APKINDEX and the two "apk version" reports
from fixtures, so no image, registry or network is involved. The indexes
are real tar.gz files with real APKINDEX records, so the script's own
tar and awk do the reading.

Shaped on the 2026-11-18 fips-140-3 v0.0.61 race: wolfi-keys
1-r15 (built at 1795023241, its real build time) was not yet in the index
that build fetched and was in the one the guard fetched minutes later. The
two "newest package" times around it are illustrative.

Run with: python3 scripts/test_check_package_freshness.py
The whole suite runs once under each bash installed at a known path (see
SHELLS), so bash 3.2 and 5.2 are both exercised where both exist.
"""

import io
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile

SCRIPT = pathlib.Path(__file__).with_name("check-package-freshness.sh")
# Every bash installed at one of these paths runs the whole suite: macOS
# ships 3.2 at /bin/bash and Homebrew installs 5.x, so both are exercised
# where both exist. Fixed paths, so nothing from the environment is run.
CANDIDATE_SHELLS = ("/bin/bash", "/usr/bin/bash", "/opt/homebrew/bin/bash",
                    "/usr/local/bin/bash")
SHELLS = sorted({os.path.realpath(p): p for p in CANDIDATE_SHELLS
                 if os.access(p, os.X_OK)}.values())
BASH = SHELLS[0] if SHELLS else "/bin/bash"
INDEX = "APKINDEX.629d04f5.tar.gz"

R15_BUILT = 1795023241          # wolfi-keys 1-r15, from the live index (real)
BUILD_INDEX_NEWEST = 1795023230  # newest package in the build's index (illustrative)
GUARD_INDEX_NEWEST = 1795023400  # newest package when the guard fetched (illustrative)

SHIM = r'''#!/usr/bin/env python3
"""Stand-in for the docker CLI calls check-package-freshness.sh makes."""
import io, os, shutil, sys, tarfile
S = os.environ["SHIM_DIR"]
args = sys.argv[1:]
with open(os.path.join(S, "calls.log"), "a") as log:
    log.write(" ".join(args) + "\n")
cmd = args[0]
if cmd == "create":
    print("cid0")
elif cmd == "rm":
    pass
elif cmd == "export":
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as out:
        root = os.path.join(S, "rootfs")
        for base, dirs, files in os.walk(root):
            for name in sorted(dirs + files):
                full = os.path.join(base, name)
                out.add(full, arcname=os.path.relpath(full, root), recursive=False)
    sys.stdout.buffer.write(buf.getvalue())
elif cmd == "cp":
    src, dest = args[1], args[2]
    path = src.split(":", 1)[1].rstrip(".").rstrip("/")
    tree = os.path.join(S, "rootfs", path.lstrip("/"))
    if not os.path.isdir(tree):
        sys.exit("Error: No such container:path: " + src)
    for name in os.listdir(tree):
        shutil.copy(os.path.join(tree, name), dest)
elif cmd == "run":
    cache = None
    if "-v" in args:
        cache = args[args.index("-v") + 1].split(":", 1)[0]
    if "update" in args:
        for name in os.listdir(os.path.join(S, "live")):
            shutil.copy(os.path.join(S, "live", name), cache)
        print("fetch https://apk.example/os/aarch64/APKINDEX.tar.gz")
        print("OK: 3 distinct packages available")
    elif "version" in args:
        if cache is None and "--network" not in args:
            sys.exit("baked-index comparison must run with --network none")
        report = "live_version.txt" if cache else "baked_version.txt"
        with open(os.path.join(S, report)) as fh:
            sys.stdout.write(fh.read())
        code = os.path.join(S, report + ".rc")
        if os.path.exists(code):
            sys.exit(int(open(code).read()))
    else:
        sys.exit("unexpected docker run: " + " ".join(args))
else:
    sys.exit("unexpected docker command: " + cmd)
'''


def index_tar(records):
    """An APKINDEX.tar.gz holding one APKINDEX file with these (P, V, t) records."""
    text = "".join(f"C:Q1x=\nP:{p}\nV:{v}\nA:aarch64\nt:{t}\n\n" for p, v, t in records)
    payload = text.encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as out:
        info = tarfile.TarInfo("APKINDEX")
        info.size = len(payload)
        out.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def run_guard(tmp, *, live, baked, live_version, baked_version,
              baked_present=True, baked_rc=None, live_name=INDEX):
    """live / baked: a record list for the one repository INDEX, or a dict of
    index file name -> record list for several repositories."""
    if not isinstance(live, dict):
        live = {live_name: live}
    if not isinstance(baked, dict):
        baked = {INDEX: baked}
    s = pathlib.Path(tmp)
    (s / "bin").mkdir()
    shim = s / "bin" / "docker"
    shim.write_text(SHIM)
    shim.chmod(0o755)
    rootfs = s / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "sbin" / "apk").write_text("")
    if baked_present:
        (rootfs / "var" / "cache" / "apk").mkdir(parents=True)
        for name, records in baked.items():
            (rootfs / "var" / "cache" / "apk" / name).write_bytes(index_tar(records))
    (s / "live").mkdir()
    for name, records in live.items():
        (s / "live" / name).write_bytes(index_tar(records))
    (s / "live_version.txt").write_text(live_version)
    (s / "baked_version.txt").write_text(baked_version)
    if baked_rc is not None:
        (s / "baked_version.txt.rc").write_text(str(baked_rc))
    (s / "tmp").mkdir()
    env = dict(os.environ, SHIM_DIR=str(s), PATH=f"{s / 'bin'}:{os.environ['PATH']}",
               TMPDIR=str(s / "tmp"))
    env.pop("RUNNER_TEMP", None)
    done = subprocess.run([BASH, str(SCRIPT), "img:test", "linux/arm64"],
                          capture_output=True, text=True, env=env, timeout=120)
    return done.returncode, done.stdout + done.stderr


HEADER = "Installed:                                Available:\n"
KEYS_STALE = HEADER + "wolfi-keys-1-r14                        < 1-r15 \n"
LIVE = [("wolfi-keys", "1-r14", 1792668781), ("wolfi-keys", "1-r15", R15_BUILT),
        ("busybox", "1.37.0-r50", GUARD_INDEX_NEWEST)]
BAKED = [("wolfi-keys", "1-r14", 1792668781), ("busybox", "1.37.0-r50", BUILD_INDEX_NEWEST)]


def test_a_package_published_after_the_build_fetched_its_index_is_not_a_failure():
    # Regression for fips-140-3 v0.0.61: the image had everything
    # its own index offered; wolfi-keys 1-r15 appeared 11 s after that index.
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_guard(tmp, live=LIVE, baked=BAKED,
                            live_version=KEYS_STALE, baked_version=HEADER)
        assert rc == 0, out
        assert "::warning::" in out and "wolfi-keys-1-r14" in out, out


def test_a_package_the_build_could_have_installed_still_fails():
    # The openjdk17-base libpng shape: r2 was in the build's own index and r0
    # shipped.
    stale = HEADER + "libpng-1.6.59-r0                        < 1.6.59-r2 \n"
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_guard(
            tmp, live=LIVE + [("libpng", "1.6.59-r2", 1794000000)],
            baked=BAKED + [("libpng", "1.6.59-r2", 1794000000)],
            live_version=stale, baked_version=stale)
        assert rc == 1, out
        assert "libpng-1.6.59-r0" in out and "older than the repository offers" in out, out


def test_a_day_old_build_index_does_not_excuse_anything():
    # An index the build did not refresh (apk update fell back to the one in
    # the base image) offers nothing new, so everything would look "late".
    old = [(p, v, t - 86400) for p, v, t in BAKED]
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_guard(tmp, live=LIVE, baked=old,
                            live_version=KEYS_STALE, baked_version=HEADER)
        assert rc == 1, out
        assert "behind the live one" in out, out


def test_an_image_without_its_build_index_fails_as_before():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_guard(tmp, live=LIVE, baked=BAKED, baked_present=False,
                            live_version=KEYS_STALE, baked_version=HEADER)
        assert rc == 1, out
        assert "no package index from its own build" in out, out


def test_a_build_index_that_apk_cannot_read_is_unknown_not_clean():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_guard(tmp, live=LIVE, baked=BAKED, live_version=KEYS_STALE,
                            baked_version="WARNING: opening index: BAD signature\n" + HEADER)
        assert rc == 1, out
        assert "UNKNOWN" in out, out


def test_a_different_set_of_repositories_does_not_excuse_anything():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_guard(tmp, live=LIVE, baked=BAKED, live_version=KEYS_STALE,
                            baked_version=HEADER, live_name="APKINDEX.0badcafe.tar.gz")
        assert rc == 1, out
        assert "same repositories" in out, out


def test_one_current_repository_does_not_vouch_for_a_stale_one():
    # Taking the newest build time across all indexes would let a fresh
    # repository hide a day-old one, so each repository is compared alone.
    other = "APKINDEX.0badcafe.tar.gz"
    live_other = [("extra", "1.0-r0", GUARD_INDEX_NEWEST - 10)]
    baked_other = [("extra", "1.0-r0", GUARD_INDEX_NEWEST - 10 - 86400)]
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_guard(tmp, live={INDEX: LIVE, other: live_other},
                            baked={INDEX: BAKED, other: baked_other},
                            live_version=KEYS_STALE, baked_version=HEADER)
        assert rc == 1, out
        assert "behind the live one" in out and "0badcafe" in out, out


def test_an_index_older_than_the_limit_excuses_nothing():
    # MAX_INDEX_LAG is 1800 s: 2000 s is too old.
    old = [(p, v, GUARD_INDEX_NEWEST - 2000) for p, v, _ in BAKED]
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_guard(tmp, live=LIVE, baked=old,
                            live_version=KEYS_STALE, baked_version=HEADER)
        assert rc == 1, out
        assert "behind the live one" in out, out


def test_an_image_index_newer_than_the_live_one_is_unknown():
    newer = [(p, v, GUARD_INDEX_NEWEST + 600) for p, v, _ in BAKED]
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_guard(tmp, live=LIVE, baked=newer,
                            live_version=KEYS_STALE, baked_version=HEADER)
        assert rc == 1, out
        assert "UNKNOWN" in out, out


def test_apk_failing_on_the_image_index_is_unknown_not_clean():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_guard(tmp, live=LIVE, baked=BAKED, live_version=KEYS_STALE,
                            baked_version=HEADER, baked_rc=1)
        assert rc == 1, out
        assert "UNKNOWN" in out, out


def test_the_guard_leaves_no_temporary_directories_behind():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_guard(tmp, live=LIVE, baked=BAKED,
                            live_version=KEYS_STALE, baked_version=HEADER)
        assert rc == 0, out
        left = sorted(p.name for p in (pathlib.Path(tmp) / "tmp").iterdir())
        assert left == [], left


def test_a_current_image_passes_without_consulting_its_own_index():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_guard(tmp, live=LIVE, baked=BAKED,
                            live_version=HEADER, baked_version="must not be read\n")
        assert rc == 0, out
        assert "every installed package is the newest" in out, out
        calls = (pathlib.Path(tmp) / "calls.log").read_text()
        assert "cp " not in calls, calls


if __name__ == "__main__":
    import traceback
    if not SHELLS:
        sys.exit(f"no bash found at any of {CANDIDATE_SHELLS}")
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    failed = []
    for shell in SHELLS:
        BASH = shell
        for name, fn in tests:
            try:
                fn()
            except BaseException:
                failed.append(f"{name} [{shell}]")
                print(f"FAIL {name} [{shell}]")
                traceback.print_exc()
            else:
                print(f"ok   {name} [{shell}]")
    total = len(tests) * len(SHELLS)
    print(f"{total - len(failed)} passed, {len(failed)} failed (shells: {', '.join(SHELLS)})")
    if failed:
        print("failed: " + ", ".join(failed))
        sys.exit(1)
