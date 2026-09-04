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

The script is deliberately strict: any unexpected layout aborts the build
rather than silently leaving a vulnerable copy in the image.
"""

from __future__ import annotations

import json
import pathlib
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

    verify(vendor, msgpack_version)
    print("harden-pip-vendor: done")


if __name__ == "__main__":
    main()
