#!/usr/bin/env python3
"""Raise pip's bundled dependencies to their fixed versions.

pip ships copies of several third-party packages under ``pip/_vendor`` and
records their provenance in ``pip/_vendor/vendor.txt`` and
``pip/_vendor/bom.cdx.json``. Scanners parse both files as an inventory of
installed packages, so pip's bundled copies surface as image vulnerabilities.

Two advisories currently apply, and both are resolved here by changing the
code that is actually present rather than by suppressing the finding:

  msgpack 1.1.2 -> 1.2.1
      GHSA-6v7p-g79w-8964. Replaced with the pure-Python sources of the
      already-installed msgpack, which sits in site-packages at a fixed
      version as a transitive dependency of poetry via cachecontrol.

  pkg_resources -> removed
      CVE-2025-47273 (fixed in setuptools 78.1.1) and CVE-2026-59890 (fixed
      in setuptools 83.0.0). setuptools deleted pkg_resources outright in
      82.0.0, so there is no release that both ships the module and carries
      both fixes; upstream's fixed state is removal. pip imports it only
      from the pkg_resources metadata backend, which cannot be selected on
      Python 3.14+ and is deprecated on earlier versions
      (see pip/_internal/metadata/__init__.py::_should_use_importlib_metadata).

A final pass then reconciles both declarations against the vendored code
itself. The distro's pip wheel carries backported fixes that upstream pip has
not released, and those backports update the code and vendor.txt while leaving
bom.cdx.json at the version the backport replaced. Scanners read the stale
declaration and report a vulnerability the image does not contain, which blocks
the build on a finding no code change can clear.

That pass derives every expected version by reading the vendored package, never
from a list kept here, so a backport of something else is handled without
editing this file. It corrects in BOTH directions: a declaration claiming a
version newer than the code on disk is just as wrong, and understates risk.
Packages whose code exposes no version are named in the output rather than
counted as checked - a vacuous pass read as a verified one is how this class of
drift hides.

The script is deliberately strict: any unexpected layout aborts the build
rather than silently leaving a vulnerable copy in the image.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import sys

MSGPACK_MIN = (1, 2, 1)
MSGPACK_MODULES = ("__init__.py", "exceptions.py", "ext.py", "fallback.py")


def fail(message: str) -> None:
    sys.exit(f"harden-pip-vendor: {message}")


def find_vendor_dir() -> pathlib.Path:
    import pip

    vendor = pathlib.Path(pip.__file__).resolve().parent / "_vendor"
    if not vendor.is_dir():
        fail(f"expected pip vendor directory at {vendor}")
    return vendor


def find_installed_msgpack() -> pathlib.Path:
    """Locate the real msgpack install, skipping pip's bundled copy."""
    import importlib.util

    spec = importlib.util.find_spec("msgpack")
    if spec is None or not spec.origin:
        fail("msgpack is not installed; cannot source fixed sources from it")
    src = pathlib.Path(spec.origin).resolve().parent
    if "_vendor" in src.parts:
        fail(f"resolved msgpack to pip's bundled copy at {src}")
    return src


def replace_vendored_msgpack(vendor: pathlib.Path) -> str:
    import msgpack

    if msgpack.version < MSGPACK_MIN:
        fail(
            f"installed msgpack {msgpack.__version__} is below the fixed "
            f"version {'.'.join(str(p) for p in MSGPACK_MIN)}"
        )

    src = find_installed_msgpack()
    dst = vendor / "msgpack"
    if not dst.is_dir():
        fail(f"expected bundled msgpack at {dst}")

    for name in MSGPACK_MODULES:
        origin = src / name
        if not origin.is_file():
            fail(f"missing {origin} in the installed msgpack")
        shutil.copyfile(origin, dst / name)

    # The compiled extension is deliberately not copied: pip's bundled copy
    # has always run the pure-Python fallback, and a .so would not be
    # importable under pip's vendored module path.
    shutil.rmtree(dst / "__pycache__", ignore_errors=True)
    return msgpack.__version__


def remove_vendored_pkg_resources(vendor: pathlib.Path) -> None:
    target = vendor / "pkg_resources"
    if not target.is_dir():
        fail(f"expected bundled pkg_resources at {target}")
    shutil.rmtree(target)


def rewrite_vendor_txt(vendor: pathlib.Path, msgpack_version: str) -> None:
    path = vendor / "vendor.txt"
    if not path.is_file():
        fail(f"expected {path}")

    kept: list[str] = []
    saw_msgpack = saw_setuptools = False
    for line in path.read_text().splitlines():
        name = line.strip().split("==")[0].strip().lower()
        if name == "msgpack":
            saw_msgpack = True
            kept.append(f"msgpack=={msgpack_version}")
        elif name == "setuptools":
            saw_setuptools = True
        else:
            kept.append(line)

    if not saw_msgpack:
        fail(f"no msgpack entry found in {path}")
    if not saw_setuptools:
        fail(f"no setuptools entry found in {path}")
    path.write_text("\n".join(kept) + "\n")


def rewrite_bom(vendor: pathlib.Path, msgpack_version: str) -> None:
    path = vendor / "bom.cdx.json"
    if not path.is_file():
        # Older pip releases predate the bundled CycloneDX BOM.
        return

    bom = json.loads(path.read_text())
    components = bom.get("components")
    if not isinstance(components, list):
        fail(f"unexpected structure in {path}: no components list")

    kept = []
    saw_msgpack = saw_setuptools = False
    for component in components:
        name = str(component.get("name", "")).lower()
        if name == "msgpack":
            saw_msgpack = True
            component["version"] = msgpack_version
            purl = component.get("purl")
            if isinstance(purl, str) and "@" in purl:
                component["purl"] = f"{purl.split('@', 1)[0]}@{msgpack_version}"
            kept.append(component)
        elif name == "setuptools":
            saw_setuptools = True
        else:
            kept.append(component)

    if not saw_msgpack:
        fail(f"no msgpack component found in {path}")
    if not saw_setuptools:
        fail(f"no setuptools component found in {path}")

    bom["components"] = kept
    path.write_text(json.dumps(bom, indent=2) + "\n")


def normalize_version(version: str) -> tuple:
    """Compare versions by value, so 2026.06.17 and 2026.6.17 are one version.

    Only differences that are real are worth rewriting; rewriting a difference
    in zero padding would churn the file on every build for no gain.
    """
    return tuple(
        int(part) if part.isdigit() else part
        for part in re.split(r"[.\-_+]", version.strip())
    )


def declared_versions(vendor: pathlib.Path) -> dict[str, str]:
    """Names and versions pip declares in vendor.txt."""
    declared: dict[str, str] = {}
    for line in (vendor / "vendor.txt").read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "==" not in stripped:
            continue
        name, _, rest = stripped.partition("==")
        declared[name.strip().lower()] = rest.split()[0].strip()
    return declared


def code_version(vendor: pathlib.Path, name: str) -> str | None:
    """Read a vendored package's version from the package itself.

    The import is done in a subprocess so a package that fails to import
    cannot take this script down with it; such a package simply reports no
    version and is listed as unverifiable.
    """
    import subprocess

    module = name.replace("-", "_")
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            f"import pip._vendor.{module} as m; print(getattr(m, '__version__', ''))",
        ],
        capture_output=True,
        text=True,
    )
    if probe.returncode == 0 and probe.stdout.strip():
        return probe.stdout.strip()

    # Not every vendored package exposes __version__ on the module; fall back
    # to a literal in its own sources before giving up.
    candidates = (
        vendor / module / "_version.py",
        vendor / module / "version.py",
        vendor / module / "__init__.py",
        vendor / f"{module}.py",
    )
    for candidate in candidates:
        if not candidate.is_file():
            continue
        found = re.search(
            r"__version__\s*[:=]\s*['\"]([^'\"]+)['\"]",
            candidate.read_text(encoding="utf-8", errors="replace"),
        )
        if found:
            return found.group(1)
    return None


def bom_versions(vendor: pathlib.Path) -> dict[str, str]:
    """Names and versions pip declares in bom.cdx.json.

    Components carrying no version are skipped: the BOM lists pip itself that
    way, and there is nothing to reconcile against.
    """
    path = vendor / "bom.cdx.json"
    if not path.is_file():
        return {}
    declared: dict[str, str] = {}
    for component in json.loads(path.read_text()).get("components", []):
        version = str(component.get("version", "")).strip()
        if version:
            declared[str(component.get("name", "")).lower()] = version
    return declared


def reconcile_declarations(vendor: pathlib.Path) -> None:
    """Make vendor.txt and bom.cdx.json agree with the vendored code.

    The two files are compared against the code independently. They disagree
    with each other as well as with the code - the distro's backport updates
    vendor.txt but not the BOM - so reconciling only the names one file
    declares would leave the other's stale entries in place.
    """
    vendor_txt = vendor / "vendor.txt"
    bom_path = vendor / "bom.cdx.json"

    from_txt = declared_versions(vendor)
    from_bom = bom_versions(vendor)

    txt_fixes: dict[str, str] = {}
    bom_fixes: dict[str, str] = {}
    unverifiable: list[str] = []

    for name in sorted(set(from_txt) | set(from_bom)):
        actual = code_version(vendor, name)
        if actual is None:
            unverifiable.append(name)
            continue
        for declared, fixes, label in (
            (from_txt.get(name), txt_fixes, "vendor.txt"),
            (from_bom.get(name), bom_fixes, "bom.cdx.json"),
        ):
            if declared is None:
                continue
            if normalize_version(actual) == normalize_version(declared):
                continue
            fixes[name] = actual
            direction = (
                "raised"
                if normalize_version(actual) > normalize_version(declared)
                else "LOWERED"
            )
            print(
                f"  {label}: {name} declared {declared}, "
                f"code has {actual} ({direction})"
            )

    if unverifiable:
        # Named rather than counted: these are the packages this pass cannot
        # vouch for, and the reader needs to know which ones they are.
        print(f"  no version readable from code: {', '.join(unverifiable)}")

    if not txt_fixes and not bom_fixes:
        print("  declarations already agree with the vendored code")
        return

    if txt_fixes:
        lines = []
        for line in vendor_txt.read_text().splitlines():
            stripped = line.strip()
            if "==" in stripped and not stripped.startswith("#"):
                declared_name = stripped.partition("==")[0].strip()
                if declared_name.lower() in txt_fixes:
                    indent = line[: len(line) - len(line.lstrip())]
                    line = (
                        f"{indent}{declared_name}=="
                        f"{txt_fixes[declared_name.lower()]}"
                    )
            lines.append(line)
        vendor_txt.write_text("\n".join(lines) + "\n")

    if bom_fixes:
        bom = json.loads(bom_path.read_text())
        for component in bom.get("components", []):
            name = str(component.get("name", "")).lower()
            if name not in bom_fixes:
                continue
            component["version"] = bom_fixes[name]
            purl = component.get("purl")
            if isinstance(purl, str) and "@" in purl:
                component["purl"] = f"{purl.split('@', 1)[0]}@{bom_fixes[name]}"
        bom_path.write_text(json.dumps(bom, indent=2) + "\n")

    print(
        f"  reconciled {len(txt_fixes)} vendor.txt and "
        f"{len(bom_fixes)} bom.cdx.json declaration(s) to the code on disk"
    )


def verify_declarations(vendor: pathlib.Path) -> None:
    """Fail the build if any readable package still disagrees with its code."""
    from_txt = declared_versions(vendor)
    from_bom = bom_versions(vendor)

    checked = 0
    for name in sorted(set(from_txt) | set(from_bom)):
        actual = code_version(vendor, name)
        if actual is None:
            continue
        checked += 1
        for label, found in (
            ("vendor.txt", from_txt.get(name)),
            ("bom.cdx.json", from_bom.get(name)),
        ):
            if found is None:
                continue
            if normalize_version(found) != normalize_version(actual):
                fail(
                    f"{label} still declares {name} {found} "
                    f"but the vendored code is {actual}"
                )
    if not checked:
        fail("no vendored package version could be read; nothing was verified")
    print(f"  ok: {checked} vendored packages match both declarations")


def verify(vendor: pathlib.Path, msgpack_version: str) -> None:
    """Confirm the result imports and reports the fixed version."""
    import subprocess

    checks = [
        (
            "bundled msgpack version",
            "import pip._vendor.msgpack as m; "
            f"assert m.__version__ == {msgpack_version!r}, m.__version__",
        ),
        (
            "pip cachecontrol serializer",
            "from pip._vendor.cachecontrol.serialize import Serializer; Serializer()",
        ),
        (
            "pip metadata backend",
            "from pip._internal.metadata import select_backend; "
            "assert select_backend().NAME == 'importlib', select_backend().NAME",
        ),
        (
            "bundled pkg_resources gone",
            "import importlib.util as u; "
            "assert u.find_spec('pip._vendor.pkg_resources') is None",
        ),
    ]
    for label, snippet in checks:
        result = subprocess.run(
            [sys.executable, "-c", snippet], capture_output=True, text=True
        )
        if result.returncode != 0:
            fail(f"verification failed ({label}): {result.stderr.strip()}")
        print(f"  ok: {label}")

    if (vendor / "pkg_resources").exists():
        fail("pkg_resources directory still present after removal")


def main() -> None:
    vendor = find_vendor_dir()
    print(f"harden-pip-vendor: hardening {vendor}")

    msgpack_version = replace_vendored_msgpack(vendor)
    print(f"  bundled msgpack raised to {msgpack_version}")

    remove_vendored_pkg_resources(vendor)
    print("  bundled pkg_resources removed (setuptools dropped it in 82.0.0)")

    rewrite_vendor_txt(vendor, msgpack_version)
    rewrite_bom(vendor, msgpack_version)
    print("  vendor.txt and bom.cdx.json updated")

    # Runs last so it sees the rewrites above and reconciles whatever the
    # distro's own backports left behind.
    reconcile_declarations(vendor)

    verify(vendor, msgpack_version)
    verify_declarations(vendor)
    print("harden-pip-vendor: done")


if __name__ == "__main__":
    main()
