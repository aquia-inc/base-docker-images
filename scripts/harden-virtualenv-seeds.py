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

The second pass therefore seeds the distro's own wheel of the same project
whenever one is present, whether its version is newer or older than the one
virtualenv bundled: a newer PyPI pip is not a patched one (virtualenv 21.15.4
bundles pip 26.3, newer than Wolfi's patched 26.2.2, and keeping it seeded
PyPI's vendored pkg_resources). No list of names or floors is kept here, so it
cannot drift out of agreement with what the distro actually ships. Projects
with no distro counterpart are named in the output rather than passed over
silently.

Every rewrite ends with the inventory describing the bytes on disk, and the
build fails unless it does: virtualenv's SBOM entry for a replaced wheel is
regenerated from that wheel (version, hashes, file and vendored entries), its
dependency references are read from the document rather than rebuilt (the
bom-ref scheme changed in virtualenv 21.15.7), and verify_inventory() checks
SBOM, RECORD and the BUNDLE tables against the wheels before the seeded
environment itself is tested.
"""

from __future__ import annotations

import ast
import base64
import email
import email.message
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


def is_under(ref: str, refs: set[str]) -> bool:
    """True for one of refs, or for anything nested under one ("<ref>#...")."""
    return ref in refs or ref.split("#", 1)[0] in refs


def prune_refs(document: dict, stale_refs: set[str]) -> None:
    """Remove every dependency node, edge and composition entry for stale_refs.

    A component's nested entries (its files and vendored packages) carry refs
    of the form "<component ref>#<path>", so those go with it.
    """
    if "dependencies" in document:
        dependencies = []
        for entry in document["dependencies"]:
            if is_under(entry.get("ref", ""), stale_refs):
                continue
            if "dependsOn" in entry:
                entry["dependsOn"] = [
                    ref for ref in entry["dependsOn"] if not is_under(ref, stale_refs)
                ]
            dependencies.append(entry)
        document["dependencies"] = dependencies

    # CycloneDX compositions list refs under both keys, and virtualenv's own
    # SBOM uses "dependencies".
    for composition in document.get("compositions", []):
        for key in ("assemblies", "dependencies"):
            if key in composition:
                composition[key] = [
                    ref for ref in composition[key] if not is_under(ref, stale_refs)
                ]


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

    for dist_info in site_packages.glob("virtualenv-*.dist-info"):
        for sbom_path in dist_info.glob("sboms/*.json"):
            document = json.loads(sbom_path.read_text(encoding="utf-8"))

            removed_components = [
                component
                for component in document.get("components", [])
                if (component.get("name"), component.get("version")) in removed_pairs
            ]
            if not removed_components:
                continue
            document["components"] = [
                component
                for component in document.get("components", [])
                if (component.get("name"), component.get("version")) not in removed_pairs
            ]

            # The references to drop are the removed components' own bom-refs,
            # read from the document rather than rebuilt from a name and
            # version: virtualenv has changed the scheme before, from
            # pkg:pypi/<name>@<version> to bundled:<wheel path> in 21.15.7,
            # and a rebuilt ref silently stops matching when it does.
            stale_refs = {
                component["bom-ref"]
                for component in removed_components
                if component.get("bom-ref")
            }
            prune_refs(document, stale_refs)

            sbom_path.write_text(
                json.dumps(document, indent=2) + "\n", encoding="utf-8"
            )
            print(
                f"  {sbom_path.name}: {len(removed_components)} component(s) "
                "removed with their dependency references"
            )

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

    virtualenv bundles wheels from PyPI. The distro ships pip with security
    backports applied to pip's own vendored tree, so its build is the one that
    belongs in the image - whatever the two version numbers say. A newer PyPI
    pip is not a patched one: virtualenv 21.15.4 bundles pip 26.3, newer than
    Wolfi's 26.2.2, and keeping it seeded PyPI's vendored pkg_resources into
    every environment virtualenv created. The seed is therefore always the
    distro wheel, newer or older, and the inventory is rewritten to describe
    it.

    Returns the names of the projects that had no distro counterpart, so the
    caller can report them rather than imply they were checked.
    """
    unmatched: list[str] = []
    swapped = 0
    site_packages = embed.parents[3]

    for wheel in sorted(embed.glob("*.whl")):
        name, version = wheel.name.split("-", 2)[:2]
        candidates = sorted(DISTRO_WHEELS.glob(f"{name}-*.whl"))
        if not candidates:
            unmatched.append(f"{name} {version}")
            continue

        # The newest distro build, if the distro somehow ships more than one.
        candidates.sort(key=lambda path: version_key(path.name.split("-", 2)[1]))
        distro = candidates[-1]
        distro_version = distro.name.split("-", 2)[1]

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

        # The SBOM and RECORD still describe the wheel virtualenv shipped:
        # its version, its hashes and the files inside it. They are rewritten
        # from the bytes now on disk, after reconcile_wheel_interior, so they
        # describe exactly what is seeded.
        describe_seed_wheel(site_packages, wheel.name, current)
        swapped += 1

    if not swapped:
        print("  no seed wheel needed replacing with a distro build")
    return unmatched


HASH_ALGORITHMS = {"SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512"}

# A vendored requirement line in pip's vendor.txt: "name==version".
VENDORED_PIN = re.compile(r"^([A-Za-z0-9._-]+)\s*==\s*([^\s;,#]+)")


def bundled_wheel_name(component: dict) -> str | None:
    """The seed wheel file an SBOM component describes, if it describes one."""
    for prop in component.get("properties", []):
        if prop.get("name") == "virtualenv:bundled-wheel":
            return str(prop.get("value", "")).rsplit("/", 1)[-1]
    return None


def wheel_dist_info(archive: zipfile.ZipFile) -> str:
    names = {name.split("/", 1)[0] for name in archive.namelist()}
    found = sorted(name for name in names if name.endswith(".dist-info"))
    if len(found) != 1:
        sys.exit(f"harden-virtualenv-seeds: expected one .dist-info in the wheel, found {found}")
    return found[0]


def python_properties(metadata: email.message.Message) -> list[dict]:
    """The python:* properties virtualenv derives from a wheel's METADATA."""
    properties = []
    if metadata.get("Requires-Python"):
        properties.append(
            {"name": "python:requires-python", "value": metadata["Requires-Python"]})
    for requirement in metadata.get_all("Requires-Dist") or []:
        properties.append({"name": "python:requires-dist", "value": requirement})
    for classifier in metadata.get_all("Classifier") or []:
        properties.append({"name": "python:classifier", "value": classifier})
    return properties


def vendored_components(archive: zipfile.ZipFile, ref: str, manifest: str) -> list[dict]:
    """One component per pin in the wheel's vendor.txt, as virtualenv writes them."""
    try:
        text = archive.read(manifest).decode("utf-8")
    except KeyError:
        sys.exit(
            f"harden-virtualenv-seeds: the replacement wheel has no {manifest}; "
            "refusing to leave its vendored inventory describing the old wheel"
        )
    components = []
    for line in text.splitlines():
        pinned = VENDORED_PIN.match(line.split("#", 1)[0].strip())
        if not pinned:
            continue
        name, version = pinned.groups()
        purl = f"pkg:pypi/{re.sub(r'[-_.]+', '-', name).lower()}@{version}"
        components.append({
            "type": "library",
            "bom-ref": f"{ref}#vendored/{purl}",
            "name": name,
            "version": version,
            "purl": purl,
            "externalReferences": [],
            "properties": [{"name": "virtualenv:vendored-manifest", "value": manifest}],
            "evidence": {"identity": [{
                "field": "purl",
                "confidence": 1,
                "methods": [{
                    "technique": "manifest-analysis",
                    "confidence": 1,
                    "value": manifest,
                }],
            }]},
        })
    return sorted(components, key=lambda component: component["purl"])


def describe_component(component: dict, old_name: str, wheel: pathlib.Path) -> str:
    """Rewrite one SBOM component in place so it describes the wheel on disk.

    Every field that names or measures the wheel is regenerated from its
    bytes: version, bom-ref, purl, the bundled-wheel property, the python:*
    properties, hashes, identity evidence, and the nested file and vendored
    components. Fields that describe the project rather than the file
    (licence, supplier, authors) are kept. The PyPI distribution link is
    dropped: the bytes are the distro's build, not the file PyPI serves.
    Returns the new bom-ref.
    """
    name, version = wheel.name.split("-", 2)[:2]
    old_ref = str(component.get("bom-ref", ""))
    old_version = str(component.get("version", ""))
    if old_name in old_ref:
        new_ref = old_ref.replace(old_name, wheel.name)
    elif old_ref == f"pkg:pypi/{name}@{old_version}":
        new_ref = f"pkg:pypi/{name}@{version}"
    else:
        sys.exit(
            f"harden-virtualenv-seeds: SBOM entry for {old_name} has bom-ref "
            f"{old_ref!r}, which names neither the wheel nor pkg:pypi/{name}@"
            f"{old_version}; refusing to guess how to rename it"
        )

    payload = wheel.read_bytes()
    with zipfile.ZipFile(wheel) as archive:
        dist_info = wheel_dist_info(archive)
        metadata = email.message_from_bytes(archive.read(f"{dist_info}/METADATA"))
        files = []
        for info in archive.infolist():
            if info.is_dir() or info.filename == f"{dist_info}/RECORD":
                continue
            data = archive.read(info.filename)
            files.append({
                "type": "file",
                "bom-ref": f"{new_ref}#{info.filename}",
                "name": info.filename,
                "hashes": [{"alg": "SHA-256",
                            "content": hashlib.sha256(data).hexdigest()}],
                "properties": [{"name": "size", "value": str(len(data))}],
            })

        libraries = [
            nested for nested in component.get("components", [])
            if nested.get("type") != "file"
        ]
        manifests = {
            prop.get("value")
            for nested in libraries
            for prop in nested.get("properties", [])
            if prop.get("name") == "virtualenv:vendored-manifest"
        }
        if libraries and not manifests:
            sys.exit(
                f"harden-virtualenv-seeds: {old_name}'s SBOM entry lists vendored "
                "packages but names no vendored-manifest for them; refusing to "
                "drop them or to guess where they came from"
            )
        if not manifests:
            vendored = []
        elif len(manifests) == 1 and next(iter(manifests)).endswith("_vendor/vendor.txt"):
            vendored = vendored_components(archive, new_ref, next(iter(manifests)))
        else:
            sys.exit(
                f"harden-virtualenv-seeds: {old_name}'s vendored inventory comes "
                f"from {sorted(manifests)}; only a vendor.txt manifest can be "
                "regenerated, so refusing to leave it describing the old wheel"
            )

    component["bom-ref"] = new_ref
    component["version"] = version
    if isinstance(component.get("purl"), str):
        component["purl"] = f"{component['purl'].split('@', 1)[0]}@{version}"
    if "description" in component and metadata.get("Summary"):
        component["description"] = metadata["Summary"]

    properties = component.get("properties", [])
    had_python = any(str(p.get("name", "")).startswith("python:") for p in properties)
    kept = []
    for prop in properties:
        if str(prop.get("name", "")).startswith("python:"):
            continue
        if prop.get("name") == "virtualenv:bundled-wheel":
            prop = {**prop, "value": str(prop["value"]).replace(old_name, wheel.name)}
        kept.append(prop)
    if had_python:
        kept.extend(python_properties(metadata))
    component["properties"] = kept

    hashes = []
    for entry in component.get("hashes", []):
        algorithm = HASH_ALGORITHMS.get(entry.get("alg"))
        if algorithm is None:
            sys.exit(
                f"harden-virtualenv-seeds: SBOM entry for {old_name} carries a "
                f"{entry.get('alg')} hash this script cannot recompute"
            )
        hashes.append({"alg": entry["alg"],
                       "content": hashlib.new(algorithm, payload).hexdigest()})
    if "hashes" in component:
        component["hashes"] = hashes

    digest = hashlib.sha256(payload).hexdigest()
    for identity in component.get("evidence", {}).get("identity", []):
        for method in identity.get("methods", []):
            if method.get("technique") == "hash-comparison":
                method["value"] = digest
            elif str(method.get("value", "")).endswith(".dist-info/METADATA"):
                method["value"] = f"{dist_info}/METADATA"

    if "externalReferences" in component:
        component["externalReferences"] = [
            reference for reference in component["externalReferences"]
            if reference.get("type") != "distribution"
        ]

    if "components" in component:
        component["components"] = files + vendored
    return new_ref


def describe_seed_wheel(site_packages: pathlib.Path, old_name: str,
                        wheel: pathlib.Path) -> None:
    """Point virtualenv's SBOM and RECORD at the seed wheel now on disk."""
    for dist_info in site_packages.glob("virtualenv-*.dist-info"):
        for sbom_path in dist_info.glob("sboms/*.json"):
            document = json.loads(sbom_path.read_text(encoding="utf-8"))
            matches = [
                component for component in document.get("components", [])
                if bundled_wheel_name(component) == old_name
            ]
            if len(matches) != 1:
                sys.exit(
                    f"harden-virtualenv-seeds: {sbom_path.name} has "
                    f"{len(matches)} entries for the seed wheel {old_name}; "
                    "refusing to leave the inventory describing a replaced wheel"
                )
            component = matches[0]
            old_ref = component["bom-ref"]
            new_ref = describe_component(component, old_name, wheel)
            children = [
                nested["bom-ref"] for nested in component.get("components", [])
                if nested.get("type") != "file"
            ]

            # The wheel's own dependency node lists its vendored packages;
            # every other reference to it moves to the new ref, and refs to
            # the old wheel's nested entries go with the old wheel.
            for entry in document.get("dependencies", []):
                if entry.get("ref") == old_ref:
                    entry["ref"] = new_ref
                    entry["dependsOn"] = children
                elif "dependsOn" in entry:
                    entry["dependsOn"] = [
                        new_ref if ref == old_ref else ref
                        for ref in entry["dependsOn"]
                        if ref == old_ref or not is_under(ref, {old_ref})
                    ]
            for composition in document.get("compositions", []):
                for key in ("assemblies", "dependencies"):
                    if key in composition:
                        composition[key] = [
                            new_ref if ref == old_ref else ref
                            for ref in composition[key]
                            if ref == old_ref or not is_under(ref, {old_ref})
                        ]
            sbom_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
            print(f"  {sbom_path.name}: {old_name} entry now describes {wheel.name}")

        record = dist_info / "RECORD"
        if record.exists():
            lines = record.read_text(encoding="utf-8").splitlines()
            renamed = [
                line.replace(old_name, wheel.name, 1)
                if line.split(",", 1)[0].endswith(f"/{old_name}") else line
                for line in lines
            ]
            if renamed != lines:
                record.write_text("\n".join(renamed) + "\n", encoding="utf-8")


def refresh_record(site_packages: pathlib.Path, embed: pathlib.Path) -> None:
    """Re-measure the RECORD lines of the files this script rewrote.

    Only the seed wheels, embed/__init__.py and the SBOMs are touched. Every
    other line is left exactly as pip wrote it, including the hashless line
    for the compiled embed/__init__: this script deletes that file, and it is
    compiled again the next time virtualenv is imported (the seeded-environment
    check below does that), so the line describes what ships.
    """
    embed_rel = embed.relative_to(site_packages).as_posix()
    for dist_info in site_packages.glob("virtualenv-*.dist-info"):
        record = dist_info / "RECORD"
        if not record.exists():
            continue
        lines = record.read_text(encoding="utf-8").splitlines()
        refreshed = []
        for line in lines:
            path = line.split(",", 1)[0]
            ours = (
                (path.startswith(f"{embed_rel}/") and path.count("/") == embed_rel.count("/") + 1
                 and (path.endswith(".whl") or path.endswith("/__init__.py")))
                or path.startswith(f"{dist_info.name}/sboms/")
            )
            if ours:
                target = site_packages / path
                if not target.is_file():
                    continue
                line = record_line(path, target.read_bytes())
            refreshed.append(line)
        if refreshed != lines:
            record.write_text("\n".join(refreshed) + "\n", encoding="utf-8")
            print("  RECORD: rewritten files re-measured")


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
        # Only the read is guarded, and only against a missing member: pip
        # releases older than the bundled CycloneDX BOM have no such file, which
        # harden-pip-vendor.py tolerates the same way. Guarding the loop as well
        # would let a KeyError raised while parsing a BOM that IS present pass
        # for an absent one, leaving the declarations unchecked but reported as
        # handled.
        try:
            bom_payload = archive.read("pip/_vendor/bom.cdx.json")
        except KeyError:
            bom_payload = None
            print("    interior: no bom.cdx.json in this wheel, nothing to reconcile")

        if bom_payload is not None:
            for component in json.loads(bom_payload).get("components", []):
                version = str(component.get("version", "")).strip()
                if version:
                    in_bom[str(component.get("name", "")).lower()] = version
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
    # from what actually survived rather than patched line by line. Filtering
    # on the surviving members instead of on the paths removed here keeps the
    # listing true by construction: an entry for a file the wheel does not
    # contain is dropped even if this pass was not what removed it.
    surviving = {info.filename for info, _ in rewritten}
    surviving.add(record_info.filename)
    record_text = []
    for line in dict(members)[record_info].decode().splitlines():
        if not line.strip():
            continue
        path = line.split(",")[0]
        if path not in surviving:
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


def bundle_tables(init: pathlib.Path) -> dict[str, dict]:
    """BUNDLE_SUPPORT and BUNDLE_SHA256 as Python evaluates them.

    Both are annotated assignments of literals in virtualenv's embed
    __init__.py. A repeated key keeps its last value, exactly as at runtime.
    """
    tables: dict[str, dict] = {}
    for node in ast.parse(init.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        else:
            continue
        if isinstance(target, ast.Name) and target.id in ("BUNDLE_SUPPORT", "BUNDLE_SHA256"):
            tables[target.id] = ast.literal_eval(value)
    return tables


def sbom_refs(document: dict) -> tuple[set[str], list[str]]:
    """(every bom-ref defined, every ref the dependency graph uses)."""
    defined: set[str] = set()

    def walk(components):
        for component in components or []:
            if component.get("bom-ref"):
                defined.add(component["bom-ref"])
            walk(component.get("components"))

    metadata = document.get("metadata", {})
    if metadata.get("component", {}).get("bom-ref"):
        defined.add(metadata["component"]["bom-ref"])
    tools = metadata.get("tools")
    if isinstance(tools, dict):
        walk(tools.get("components"))
    walk(document.get("components"))

    used: list[str] = []
    for entry in document.get("dependencies", []):
        used.append(entry.get("ref", ""))
        used.extend(entry.get("dependsOn", []))
    for composition in document.get("compositions", []):
        used.extend(composition.get("assemblies", []))
        used.extend(composition.get("dependencies", []))
    return defined, used


def vendored_problems(sbom_name: str, wheel_name: str, component: dict,
                      archive: zipfile.ZipFile) -> list[str]:
    """Compare an SBOM entry's vendored packages with the wheel it describes.

    Every non-file nested entry must name the manifest it came from. Entries
    from a vendor.txt manifest must be exactly the pins that manifest holds
    in the wheel on disk. Entries from other manifests (setuptools lists its
    vendored dist-info METADATA files) are not regenerated by this script
    and are left to virtualenv.
    """
    problems = []
    by_manifest: dict[str, set[str]] = defaultdict(set)
    for nested in component.get("components", []):
        if nested.get("type") == "file":
            continue
        manifests = [prop.get("value") for prop in nested.get("properties", [])
                     if prop.get("name") == "virtualenv:vendored-manifest"]
        if len(manifests) != 1:
            problems.append(f"{sbom_name}: {wheel_name} vendored entry "
                            f"{nested.get('name')} names {len(manifests)} manifests")
            continue
        by_manifest[str(manifests[0])].add(str(nested.get("purl")))
    for manifest, purls in sorted(by_manifest.items()):
        if not manifest.endswith("_vendor/vendor.txt"):
            continue
        try:
            text = archive.read(manifest).decode("utf-8")
        except KeyError:
            problems.append(f"{sbom_name}: {wheel_name} vendored entries name {manifest}, "
                            "which the wheel does not contain")
            continue
        expected = set()
        for line in text.splitlines():
            pinned = VENDORED_PIN.match(line.split("#", 1)[0].strip())
            if pinned:
                name, version = pinned.groups()
                expected.add(f"pkg:pypi/{re.sub(r'[-_.]+', '-', name).lower()}@{version}")
        if purls != expected:
            problems.append(
                f"{sbom_name}: {wheel_name} vendored entries do not match its {manifest} "
                f"(only in SBOM: {sorted(purls - expected)}; only in the wheel: "
                f"{sorted(expected - purls)})")
    return problems


def verify_inventory(embed: pathlib.Path, site_packages: pathlib.Path) -> None:
    """Fail the build unless virtualenv's inventory describes the seed wheels on disk.

    Checked against the bytes, never against version strings: a version can
    appear legitimately elsewhere (packaging>=26.3 is a requirement, not pip
    26.3). For every seed wheel on disk: BUNDLE_SHA256 holds its digest and
    BUNDLE_SUPPORT names only wheels that exist; each SBOM has exactly one
    entry for it, with its version and digest, and file entries that match
    the wheel's members; RECORD lists it with its digest. Every reference in
    the SBOM's dependency graph and compositions resolves.
    """
    problems: list[str] = []
    wheels = {
        wheel.name: wheel.read_bytes() for wheel in sorted(embed.glob("*.whl"))
    }
    digests = {name: hashlib.sha256(data).hexdigest() for name, data in wheels.items()}

    tables = bundle_tables(embed / "__init__.py")
    if "BUNDLE_SHA256" in tables:
        for name, digest in digests.items():
            if tables["BUNDLE_SHA256"].get(name) != digest:
                problems.append(f"BUNDLE_SHA256 does not hold the digest of {name}")
    for per_python in tables.get("BUNDLE_SUPPORT", {}).values():
        for name in per_python.values():
            if name not in wheels:
                problems.append(f"BUNDLE_SUPPORT names {name}, which is not on disk")

    for dist_info in site_packages.glob("virtualenv-*.dist-info"):
        for sbom_path in dist_info.glob("sboms/*.json"):
            document = json.loads(sbom_path.read_text(encoding="utf-8"))
            described: dict[str, list] = defaultdict(list)
            for component in document.get("components", []):
                name = bundled_wheel_name(component)
                if name:
                    described[name].append(component)
            for name in sorted(set(described) - set(wheels)):
                problems.append(f"{sbom_path.name} describes {name}, which is not on disk")
            # A seed project declared at the top level without naming its wheel
            # (a plain "pip 26.3" component) is a version scanners would report.
            seed_projects = {name.split("-", 1)[0].lower() for name in wheels}
            for component in document.get("components", []):
                if (bundled_wheel_name(component) is None
                        and str(component.get("name", "")).lower() in seed_projects
                        and component.get("version")):
                    problems.append(f"{sbom_path.name} declares {component.get('name')} "
                                    f"{component.get('version')} without a seed wheel")
            for name, data in wheels.items():
                entries = described.get(name, [])
                if len(entries) != 1:
                    problems.append(f"{sbom_path.name} has {len(entries)} entries for {name}")
                    continue
                component = entries[0]
                version = name.split("-", 2)[1]
                if component.get("version") != version:
                    problems.append(f"{sbom_path.name}: {name} declared as version "
                                    f"{component.get('version')}")
                purl = component.get("purl")
                if isinstance(purl, str) and not purl.endswith(f"@{version}"):
                    problems.append(f"{sbom_path.name}: {name} purl {purl} names "
                                    "another version")
                sha = [h.get("content") for h in component.get("hashes", [])
                       if h.get("alg") == "SHA-256"]
                if sha != [digests[name]]:
                    problems.append(f"{sbom_path.name}: {name} SHA-256 is not the file's")
                if "components" not in component:
                    continue
                # Every member but the wheel's own RECORD, which cannot list its
                # own hash. RECORDs of vendored dist-info directories are listed.
                with zipfile.ZipFile(embed / name) as archive:
                    own_record = f"{wheel_dist_info(archive)}/RECORD"
                    members = {
                        info.filename: hashlib.sha256(archive.read(info.filename)).hexdigest()
                        for info in archive.infolist()
                        if not info.is_dir() and info.filename != own_record
                    }
                    listed = {
                        nested.get("name"): (nested.get("hashes") or [{}])[0].get("content")
                        for nested in component["components"]
                        if nested.get("type") == "file"
                    }
                    if listed != members:
                        problems.append(f"{sbom_path.name}: {name} file entries do not "
                                        "match the wheel's contents")
                    problems.extend(
                        vendored_problems(sbom_path.name, name, component, archive))

            defined, used = sbom_refs(document)
            dangling = sorted({ref for ref in used if ref not in defined})
            if dangling:
                problems.append(f"{sbom_path.name}: {len(dangling)} dangling reference(s), "
                                f"first {dangling[0]}")

        record = dist_info / "RECORD"
        if record.exists():
            embed_rel = embed.relative_to(site_packages).as_posix()
            lines = record.read_text(encoding="utf-8").splitlines()
            listed = {
                line.split(",", 1)[0].rsplit("/", 1)[-1]: line
                for line in lines
                if line.split(",", 1)[0].startswith(f"{embed_rel}/")
                and line.split(",", 1)[0].endswith(".whl")
            }
            for name in sorted(set(listed) - set(wheels)):
                problems.append(f"RECORD lists {name}, which is not on disk")
            for name, data in wheels.items():
                if listed.get(name) != record_line(f"{embed_rel}/{name}", data):
                    problems.append(f"RECORD does not list {name} with its digest and size")
            # The other files this script rewrites: embed/__init__.py and the SBOMs.
            for line in lines:
                path = line.split(",", 1)[0]
                if path == f"{embed_rel}/__init__.py" or path.startswith(
                        f"{dist_info.name}/sboms/"):
                    target = site_packages / path
                    if not target.is_file() or line != record_line(path, target.read_bytes()):
                        problems.append(f"RECORD does not list {path} with its digest and size")

    if problems:
        sys.exit("harden-virtualenv-seeds: the inventory does not describe the seed "
                 "wheels on disk:\n  " + "\n  ".join(problems))
    print(f"  verified: SBOM, RECORD and BUNDLE tables describe the {len(wheels)} "
          "seed wheel(s) on disk, and every SBOM reference resolves")


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

    refresh_record(site_packages, embed)
    verify_inventory(embed, site_packages)
    verify_seeded_environment()
    print("harden-virtualenv-seeds: done")


if __name__ == "__main__":
    main()
