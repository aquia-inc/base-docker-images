#!/usr/bin/env python3
"""Remove virtualenv's superseded seed wheels and correct its inventory.

virtualenv ships several pip and setuptools wheels under
``virtualenv/seed/wheels/embed`` so it can seed a new environment without a
network fetch. It keeps one set per supported Python version, so the copies
used for older interpreters stay behind at their original versions and keep
their original vulnerabilities.

At the time of writing that is pip 26.0.1 (CVE-2026-13346, CVE-2026-3219,
CVE-2026-6357, CVE-2026-8643) and setuptools 82.0.1 (CVE-2026-59890), both
referenced only by the Python 3.9 entry. This image ships a single Python
version, so those wheels can never be selected here.

Three things make this worth a script rather than an ignore rule:

  * There is no installable fix. virtualenv 21.9.1, the current release, still
    bundles exactly those wheels, and virtualenv cannot simply be dropped
    because poetry imports it to create environments.

  * Deleting the wheel files alone does not resolve the finding. virtualenv
    publishes its own CycloneDX SBOM at
    ``virtualenv-<version>.dist-info/sboms/virtualenv.cdx.json`` and lists the
    wheels in ``RECORD``. Scanners read that declared inventory, which is why
    the finding reports no file path. The inventory has to agree with what is
    actually on disk.

  * A suppression would not reach anyone downstream. Consumers scan the
    published image with their own tooling and never see this repository's
    ignore file, so suppressing here would leave them looking at findings we
    had quietly accepted.

The order below is deliberate and is what keeps the result honest: the
vulnerable wheels are deleted first, and only then is the inventory rewritten
to describe what remains. Editing the SBOM without removing the files would
misreport the contents of the image.

Nothing is pinned to a version. The highest version present of each project is
kept and every older copy is removed, so a future virtualenv that bundles a new
stale wheel is handled without editing this file.

Removing the superseded copies is not sufficient on its own. The wheel that
survives is the one virtualenv actually seeds into every environment it
creates, and its INTERIOR carries its own vendored tree. virtualenv takes that
wheel from PyPI, so it ships the unpatched vendored code even when the distro
packages a patched build of the identical version - currently urllib3 2.7.0
against the distro's 2.8.0. No scanner reads inside a .whl, so an image can
seed a vulnerable pip into every environment while scanning perfectly clean.

The second pass therefore prefers the distro's own wheel of the same project
whenever one is present and not older. That is deliberately framed as "not
behind the distro-patched copy of the same artifact" rather than a list of
names and floors kept here: it is self-healing, and it cannot drift out of
agreement with what the distro actually ships. Projects with no distro
counterpart are named in the output rather than passed over silently.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import re
import sys
import zipfile
from collections import defaultdict

LIB_ROOT = pathlib.Path("/home/nonroot/.local/lib")

# Where the distro keeps the wheels it has applied its backports to.
DISTRO_WHEELS = pathlib.Path("/usr/share/python-wheels")

# The embed directory is located by glob rather than a fixed path because the
# python3 compatibility symlink is created later in the Dockerfile and does not
# exist yet when this runs.
EMBED_GLOB = "python3*/site-packages/virtualenv/seed/wheels/embed"


def version_key(version: str) -> tuple:
    """Numeric-aware sort key, so 26.10 sorts above 26.2."""
    return tuple(
        int(part) if part.isdigit() else part
        for part in re.split(r"[.\-]", version)
    )


def find_embed() -> pathlib.Path:
    matches = sorted(LIB_ROOT.glob(EMBED_GLOB))
    if not matches:
        sys.exit(f"harden-virtualenv-seeds: no seed wheels found under {LIB_ROOT}")
    return matches[-1]


def remove_superseded(embed: pathlib.Path) -> dict[str, str]:
    """Delete all but the highest version of each bundled project.

    Returns a mapping of removed wheel filename to the filename kept in its
    place, which the inventory rewrites below use.
    """
    grouped: dict[str, list] = defaultdict(list)
    for wheel in embed.glob("*.whl"):
        name, version = wheel.name.split("-", 2)[:2]
        grouped[name].append((version_key(version), version, wheel))

    replacements: dict[str, str] = {}
    for name, entries in sorted(grouped.items()):
        entries.sort()
        kept = entries[-1]
        print(f"  keeping {name} {kept[1]}")
        for _, version, wheel in entries[:-1]:
            print(f"  removing superseded {name} {version}")
            replacements[wheel.name] = kept[2].name
            wheel.unlink()
    return replacements


def rewrite_bundle_support(embed: pathlib.Path, replacements: dict[str, str]) -> None:
    """Point BUNDLE_SUPPORT at the wheels that are still present."""
    init = embed / "__init__.py"
    original = init.read_text(encoding="utf-8")
    updated = original
    for removed, kept in replacements.items():
        updated = updated.replace(removed, kept)
    if updated != original:
        init.write_text(updated, encoding="utf-8")
        print("  BUNDLE_SUPPORT re-pointed")
    for cached in embed.glob("__pycache__/*.pyc"):
        cached.unlink()


def rewrite_inventory(site_packages: pathlib.Path, replacements: dict[str, str]) -> None:
    """Drop the removed wheels from the shipped CycloneDX SBOM and RECORD.

    These are what scanners read as the inventory, which is why the finding
    reports no file path. The components are REMOVED rather than relabelled:
    the image no longer contains those versions at all, so deleting the entry
    is the accurate description. Rewriting a version in place would instead
    leave a duplicate component and dangling bom-ref, purl and dependency
    references pointing at a package that is not there.
    """
    removed_pairs = {
        (removed.split("-", 2)[0], removed.split("-", 2)[1])
        for removed in replacements
    }
    stale_refs = {f"pkg:pypi/{name}@{version}" for name, version in removed_pairs}

    for dist_info in site_packages.glob("virtualenv-*.dist-info"):
        for sbom_path in dist_info.glob("sboms/*.json"):
            document = json.loads(sbom_path.read_text(encoding="utf-8"))

            kept_components = [
                component
                for component in document.get("components", [])
                if (component.get("name"), component.get("version")) not in removed_pairs
            ]
            dropped = len(document.get("components", [])) - len(kept_components)
            if not dropped:
                continue
            document["components"] = kept_components

            # Drop dependency nodes for the removed refs, and any edge to them.
            dependencies = []
            for entry in document.get("dependencies", []):
                if entry.get("ref") in stale_refs:
                    continue
                if "dependsOn" in entry:
                    entry["dependsOn"] = [
                        ref for ref in entry["dependsOn"] if ref not in stale_refs
                    ]
                dependencies.append(entry)
            if "dependencies" in document:
                document["dependencies"] = dependencies

            for composition in document.get("compositions", []):
                if "assemblies" in composition:
                    composition["assemblies"] = [
                        ref
                        for ref in composition["assemblies"]
                        if ref not in stale_refs
                    ]

            sbom_path.write_text(
                json.dumps(document, indent=2) + "\n", encoding="utf-8"
            )
            print(f"  {sbom_path.name}: {dropped} component(s) removed")

        record = dist_info / "RECORD"
        if not record.exists():
            continue
        original = record.read_text(encoding="utf-8")
        kept_lines = [
            line
            for line in original.splitlines(keepends=True)
            if not any(removed in line for removed in replacements)
        ]
        if len(kept_lines) != len(original.splitlines(keepends=True)):
            record.write_text("".join(kept_lines), encoding="utf-8")
            print("  RECORD: removed wheel entries dropped")


def prefer_distro_wheels(embed: pathlib.Path) -> list[str]:
    """Replace each seed wheel with the distro's build of the same project.

    virtualenv bundles wheels from PyPI. The distro ships the same pip version
    with security backports applied to pip's own vendored tree, so the two
    differ in content while agreeing on version. The distro build is the one
    that belongs in the image.

    Returns the names of the projects that had no distro counterpart, so the
    caller can report them rather than imply they were checked.
    """
    unmatched: list[str] = []
    swapped = 0

    for wheel in sorted(embed.glob("*.whl")):
        name, version = wheel.name.split("-", 2)[:2]
        candidates = sorted(DISTRO_WHEELS.glob(f"{name}-*.whl"))
        if not candidates:
            unmatched.append(f"{name} {version}")
            continue

        # Take the newest distro build, and never move backwards.
        candidates.sort(key=lambda path: version_key(path.name.split("-", 2)[1]))
        distro = candidates[-1]
        distro_version = distro.name.split("-", 2)[1]
        if version_key(distro_version) < version_key(version):
            print(
                f"  {name}: distro has {distro_version}, bundled has {version}; "
                "keeping the bundled copy"
            )
            continue

        before = wheel.read_bytes()
        after = distro.read_bytes()
        old_digest = hashlib.sha256(before).hexdigest()

        if before == after:
            print(f"  {name} {version}: already identical to the distro wheel")
            current = wheel
        elif version_key(distro_version) != version_key(version):
            # A different version means a different filename, which
            # BUNDLE_SUPPORT refers to by name.
            current = embed / distro.name
            current.write_bytes(after)
            wheel.unlink()
            rewrite_bundle_support(embed, {wheel.name: distro.name})
            print(
                f"  {name}: seed wheel replaced with the distro build "
                f"({version} -> {distro_version})"
            )
        else:
            wheel.write_bytes(after)
            current = wheel
            print(
                f"  {name}: seed wheel replaced with the distro build "
                f"({version} -> {distro_version})"
            )

        # The distro build is closer to correct but not correct: its interior
        # declarations still describe the versions its own backport replaced.
        reconcile_wheel_interior(current)

        new_digest = hashlib.sha256(current.read_bytes()).hexdigest()
        if new_digest == old_digest:
            continue

        # virtualenv hashes each bundled wheel before handing it to pip and
        # raises on a mismatch, so the recorded digest has to move with the
        # bytes. The stale literal is replaced wherever it appears: the
        # rename above can leave more than one entry keyed by the same name.
        init = embed / "__init__.py"
        source = init.read_text(encoding="utf-8")
        if old_digest not in source:
            sys.exit(
                f"harden-virtualenv-seeds: {name} {version} sha256 {old_digest} "
                "is not recorded in BUNDLE_SHA256; refusing to leave an "
                "unverifiable wheel in place"
            )
        init.write_text(source.replace(old_digest, new_digest), encoding="utf-8")
        for cached in embed.glob("__pycache__/*.pyc"):
            cached.unlink()
        swapped += 1

    if not swapped:
        print("  no seed wheel needed replacing with a distro build")
    return unmatched


def code_version_in_wheel(archive: zipfile.ZipFile, name: str) -> str | None:
    """Read a vendored package's version from its sources inside the wheel."""
    module = name.replace("-", "_")
    for candidate in (
        f"pip/_vendor/{module}/_version.py",
        f"pip/_vendor/{module}/version.py",
        f"pip/_vendor/{module}/package_data.py",
        f"pip/_vendor/{module}/__about__.py",
        f"pip/_vendor/{module}/__init__.py",
        f"pip/_vendor/{module}.py",
    ):
        try:
            source = archive.read(candidate).decode("utf-8", errors="replace")
        except KeyError:
            continue
        for line in source.splitlines():
            # Must be an assignment of a version literal. Matching any quoted
            # string on a line that merely mentions __version__ picks up
            # import statements and f-strings instead, which is why the
            # captured value is required to start with a digit.
            assigned = re.match(
                r"""__version__\s*(?::\s*[^=]+?)?=\s*"""
                r"""(?:[A-Za-z_][A-Za-z_0-9]*\s*=\s*)*"""
                r"""['"]([0-9][^'"]*)['"]""",
                line.strip(),
            )
            if assigned:
                return assigned.group(1)
    return None


def record_line(path: str, payload: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest())
    return f"{path},sha256={digest.rstrip(b'=').decode()},{len(payload)}"


def reconcile_wheel_interior(wheel: pathlib.Path) -> bool:
    """Correct the declarations and vendored code inside a seed wheel.

    The seed wheel is what virtualenv unpacks into every environment it
    creates, so its interior is what consumers end up scanning. Two things are
    wrong in it even after taking the distro's build:

      * ``pip/_vendor/bom.cdx.json`` is left at the versions the distro's
        backport replaced, so it declares urllib3 and msgpack versions the
        wheel does not contain.

      * ``pip/_vendor/pkg_resources`` is present. That is the setuptools code
        the ``setuptools`` entry refers to, and it carries CVE-2025-47273 and
        CVE-2026-59890 with no release that both ships the module and fixes
        them - upstream's fixed state is removal, which is what
        harden-pip-vendor.py already does for the installed pip.

    Both are corrected here so the seeded environment matches the one the
    image itself ships. Returns True when the wheel was rewritten.
    """
    with zipfile.ZipFile(wheel) as archive:
        members = [(info, archive.read(info.filename)) for info in archive.infolist()]
        declared = {}
        for line in archive.read("pip/_vendor/vendor.txt").decode().splitlines():
            stripped = line.strip()
            if "==" in stripped and not stripped.startswith("#"):
                declared[stripped.partition("==")[0].strip().lower()] = stripped
        actual = {
            name: code_version_in_wheel(archive, name) for name in declared
        }
        in_bom = {}
        try:
            for component in json.loads(
                archive.read("pip/_vendor/bom.cdx.json")
            ).get("components", []):
                version = str(component.get("version", "")).strip()
                if version:
                    in_bom[str(component.get("name", "")).lower()] = version
        except KeyError:
            pass
        has_pkg_resources = any(
            info.filename.startswith("pip/_vendor/pkg_resources/")
            for info, _ in members
        )

    drop_prefixes = ("pip/_vendor/pkg_resources/",) if has_pkg_resources else ()

    # Both declarations are compared against the code independently. They
    # disagree with each other as well as with it, so correcting only the
    # names one file gets wrong leaves the other's stale entries behind.
    corrections: dict[str, str] = {}
    for name, version in actual.items():
        if version is None:
            continue
        declared_txt = declared[name].partition("==")[2].split()[0]
        stale_txt = version_key(version) != version_key(declared_txt)
        stale_bom = name in in_bom and version_key(version) != version_key(
            in_bom[name]
        )
        if stale_txt or stale_bom:
            corrections[name] = version

    # Where the code carries no readable version, vendor.txt is the better
    # declaration: it is pip's primary one and the distro's backport updates
    # it. Aligning the BOM to it removes a contradiction between two files in
    # the same wheel without inventing a version for either. Writing the same
    # value back to vendor.txt is a no-op, which is why these can share the
    # correction map.
    for name, version in actual.items():
        if version is not None or name in corrections:
            continue
        declared_txt = declared[name].partition("==")[2].split()[0]
        if name in in_bom and version_key(in_bom[name]) != version_key(declared_txt):
            corrections[name] = declared_txt
            print(
                f"    interior: {name} has no readable version in code; "
                f"aligning bom.cdx.json {in_bom[name]} to vendor.txt "
                f"{declared_txt}"
            )

    if not corrections and not drop_prefixes:
        print("    wheel interior already consistent")
        return False

    for name, version in sorted(corrections.items()):
        print(
            f"    interior: {name} code has {version}, declared "
            f"{declared[name].partition('==')[2].split()[0]} in vendor.txt "
            f"and {in_bom.get(name, '-')} in bom.cdx.json"
        )
    unreadable = sorted(name for name, version in actual.items() if version is None)
    if unreadable:
        print(f"    interior: no version readable from code: {', '.join(unreadable)}")
    if drop_prefixes:
        print("    interior: removing vendored pkg_resources and its declaration")

    rewritten: list[tuple[zipfile.ZipInfo, bytes]] = []
    record_info = None
    changed_records: dict[str, str] = {}
    dropped_paths: set[str] = set()

    for info, payload in members:
        if any(info.filename.startswith(prefix) for prefix in drop_prefixes):
            dropped_paths.add(info.filename)
            continue
        if info.filename.endswith(".dist-info/RECORD"):
            record_info = info
            continue

        if info.filename == "pip/_vendor/vendor.txt":
            lines = []
            for line in payload.decode().splitlines():
                stripped = line.strip()
                if "==" in stripped and not stripped.startswith("#"):
                    name = stripped.partition("==")[0].strip().lower()
                    if drop_prefixes and name == "setuptools":
                        continue
                    if name in corrections:
                        indent = line[: len(line) - len(line.lstrip())]
                        project = stripped.partition("==")[0].strip()
                        line = f"{indent}{project}=={corrections[name]}"
                lines.append(line)
            payload = ("\n".join(lines) + "\n").encode()
            changed_records[info.filename] = record_line(info.filename, payload)

        elif info.filename == "pip/_vendor/bom.cdx.json":
            document = json.loads(payload)
            kept = []
            for component in document.get("components", []):
                name = str(component.get("name", "")).lower()
                if drop_prefixes and name == "setuptools":
                    continue
                if name in corrections:
                    component["version"] = corrections[name]
                    purl = component.get("purl")
                    if isinstance(purl, str) and "@" in purl:
                        component["purl"] = (
                            f"{purl.split('@', 1)[0]}@{corrections[name]}"
                        )
                kept.append(component)
            document["components"] = kept
            payload = (json.dumps(document, indent=2) + "\n").encode()
            changed_records[info.filename] = record_line(info.filename, payload)

        rewritten.append((info, payload))

    if record_info is None:
        sys.exit(
            f"harden-virtualenv-seeds: {wheel.name} has no RECORD; refusing to "
            "repack a wheel whose integrity listing cannot be updated"
        )

    # RECORD describes every other file in the wheel, so it is rebuilt last
    # from what actually survived rather than patched line by line.
    record_text = []
    for line in dict(members)[record_info].decode().splitlines():
        if not line.strip():
            continue
        path = line.split(",")[0]
        if path in dropped_paths:
            continue
        record_text.append(changed_records.get(path, line))
    record_payload = ("\n".join(record_text) + "\n").encode()

    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as out:
        for info, payload in rewritten:
            out.writestr(info, payload)
        out.writestr(record_info, record_payload)

    print(f"    wheel interior rewritten ({len(dropped_paths)} file(s) removed)")
    return True


def verify_seeded_environment() -> None:
    """Create a real environment and read its pip's vendored tree from disk.

    Versions alone would not prove this: the wheel is only exercised when
    virtualenv seeds it, and reading ``pip._vendor`` from the current
    interpreter reports the SYSTEM pip, not the one the environment received.
    """
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        target = pathlib.Path(tmp) / "env"
        # --app-data keeps virtualenv's unpacked copy of the seed wheel inside
        # the temporary directory. Without it the check leaves an extracted
        # pip tree in the image's cache, which both ships a second copy of
        # every vendored package and is read by scanners as installed content.
        created = subprocess.run(
            [
                sys.executable, "-m", "virtualenv",
                "--app-data", str(pathlib.Path(tmp) / "app-data"),
                str(target),
            ],
            capture_output=True, text=True,
        )
        if created.returncode != 0:
            sys.exit(
                "harden-virtualenv-seeds: virtualenv could not create an "
                f"environment after hardening: {created.stderr.strip()}"
            )

        vendored = sorted(target.glob("lib/python3*/site-packages/pip/_vendor"))
        if not vendored:
            sys.exit(
                "harden-virtualenv-seeds: the created environment has no "
                "seeded pip to check"
            )

        vendor = vendored[0]
        text = vendor / "vendor.txt"
        declared = {}
        for line in text.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if "==" in stripped and not stripped.startswith("#"):
                declared[stripped.partition("==")[0].strip().lower()] = (
                    stripped.partition("==")[2].split()[0]
                )

        # The declarations in the environment must match its own code, or a
        # consumer scanning the environment sees versions it does not have.
        bom = vendor / "bom.cdx.json"
        if bom.is_file():
            for component in json.loads(bom.read_text()).get("components", []):
                name = str(component.get("name", "")).lower()
                version = str(component.get("version", "")).strip()
                if not version or name not in declared:
                    continue
                if version_key(version) != version_key(declared[name]):
                    sys.exit(
                        "harden-virtualenv-seeds: the seeded environment "
                        f"declares {name} {version} in bom.cdx.json but "
                        f"{declared[name]} in vendor.txt"
                    )

        if (vendor / "pkg_resources").exists():
            sys.exit(
                "harden-virtualenv-seeds: the seeded environment still "
                "contains pip/_vendor/pkg_resources"
            )

        # Function, not just versions: the seeded pip has to actually run,
        # and it is the vendored tree that was changed underneath it.
        pip_run = subprocess.run(
            [str(target / "bin" / "pip"), "--version"],
            capture_output=True, text=True,
        )
        if pip_run.returncode != 0:
            sys.exit(
                "harden-virtualenv-seeds: the seeded pip does not run: "
                f"{pip_run.stderr.strip()}"
            )

        print("  seeded environment vendored versions:")
        for name, version in sorted(declared.items()):
            print(f"    {name}=={version}")
        print(f"  seeded pip runs: {pip_run.stdout.strip()}")


def verify(embed: pathlib.Path, site_packages: pathlib.Path,
           replacements: dict[str, str]) -> None:
    """Fail the build if a removed version is still present or still declared.

    Only the surfaces that describe what the image contains are checked: the
    wheel files themselves, BUNDLE_SUPPORT, the CycloneDX SBOM and RECORD.

    Licence and attribution files such as THIRD-PARTY-NOTICES.md are
    deliberately excluded. They record the provenance of code virtualenv was
    distributed with and are not an inventory of what is installed; rewriting
    them would falsify an attribution record to satisfy a scanner that does
    not read them.
    """
    stale_versions = {removed.split("-", 2)[1] for removed in replacements}

    targets: list[pathlib.Path] = [embed / "__init__.py"]
    targets.extend(embed.glob("*.whl"))
    for dist_info in site_packages.glob("virtualenv-*.dist-info"):
        targets.extend(dist_info.glob("sboms/*.json"))
        record = dist_info / "RECORD"
        if record.exists():
            targets.append(record)

    for path in targets:
        if not path.is_file():
            continue

        # Wheels are zip archives, so only their file name carries a version.
        # Every other target is text and must be readable: a verification step
        # that cannot read what it is checking has to fail rather than report
        # success on the file name alone.
        haystack = path.name
        if path.suffix != ".whl":
            try:
                haystack += path.read_text(encoding="utf-8")
            except OSError as error:
                sys.exit(
                    f"harden-virtualenv-seeds: cannot read {path} "
                    f"to verify it: {error}"
                )

        for version in sorted(stale_versions):
            if version in haystack:
                sys.exit(
                    "harden-virtualenv-seeds: "
                    f"{path} still references {version}"
                )
    print("  verified: superseded versions gone from wheels, "
          "BUNDLE_SUPPORT, SBOM and RECORD")


def main() -> None:
    embed = find_embed()
    site_packages = embed.parents[3]
    print(f"harden-virtualenv-seeds: hardening {embed}")

    replacements = remove_superseded(embed)
    if replacements:
        rewrite_bundle_support(embed, replacements)
        rewrite_inventory(site_packages, replacements)
        verify(embed, site_packages, replacements)
    else:
        print("  nothing superseded")

    # Always runs, including when nothing was superseded: the surviving wheel
    # is the one that gets seeded, and its interior is the exposure.
    unmatched = prefer_distro_wheels(embed)
    if unmatched:
        print(f"  no distro wheel to compare against: {', '.join(unmatched)}")

    verify_seeded_environment()
    print("harden-virtualenv-seeds: done")


if __name__ == "__main__":
    main()
