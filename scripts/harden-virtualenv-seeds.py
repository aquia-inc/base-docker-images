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
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from collections import defaultdict

LIB_ROOT = pathlib.Path("/home/nonroot/.local/lib")

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
        haystack = path.name
        try:
            haystack += path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            pass
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
    if not replacements:
        print("harden-virtualenv-seeds: nothing superseded, done")
        return

    rewrite_bundle_support(embed, replacements)
    rewrite_inventory(site_packages, replacements)
    verify(embed, site_packages, replacements)
    print("harden-virtualenv-seeds: done")


if __name__ == "__main__":
    main()
