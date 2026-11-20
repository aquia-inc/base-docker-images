"""Unit tests for the seed wheel hardening in harden-virtualenv-seeds.py.

Hermetic: each fixture is a synthetic wheel built in a temporary directory,
or a trimmed copy of virtualenv's real SBOM under testdata/, so these run
without Docker, without a network and without a built image.

prefer_distro_wheels runs against a synthetic site-packages and distro wheel
directory. verify_seeded_environment needs a real interpreter tree, so it is
exercised by the image build instead, which fails closed if it misbehaves.
"""

import importlib.util
import json
import pathlib
import sys
import tempfile
import zipfile

_spec = importlib.util.spec_from_file_location(
    "harden_virtualenv_seeds",
    pathlib.Path(__file__).with_name("harden-virtualenv-seeds.py"))
hvs = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = hvs
_spec.loader.exec_module(hvs)

DIST_INFO = "pip-1.0.0.dist-info"


def build_wheel(tmp, declared, bom, code, pkg_resources=True,
                extra_record=(), omit_bom=False):
    """Create a synthetic pip wheel with a consistent RECORD.

    declared: list of (name, version, indented) written to vendor.txt
    bom:      dict name -> version written to bom.cdx.json
    code:     dict name -> version or None, written into package sources
    """
    files = {}

    lines = []
    for name, version, indented in declared:
        lines.append(f"{'    ' if indented else ''}{name}=={version}")
    files["pip/_vendor/vendor.txt"] = ("\n".join(lines) + "\n").encode()

    if not omit_bom:
        files["pip/_vendor/bom.cdx.json"] = (json.dumps({"components": [
            {"name": n, "version": v, "purl": f"pkg:pypi/{n}@{v}"}
            for n, v in bom.items()
        ]}, indent=2) + "\n").encode()

    for name, version in code.items():
        module = name.replace("-", "_")
        if version is None:
            files[f"pip/_vendor/{module}/__init__.py"] = (
                b"from .data import __version__\n")
        else:
            files[f"pip/_vendor/{module}/_version.py"] = (
                f"__version__ = version = '{version}'\n".encode())

    if pkg_resources:
        files["pip/_vendor/pkg_resources/__init__.py"] = b"# setuptools code\n"

    record = [hvs.record_line(path, payload) for path, payload in files.items()]
    record.extend(extra_record)
    record.append(f"{DIST_INFO}/RECORD,,")
    files[f"{DIST_INFO}/RECORD"] = ("\n".join(record) + "\n").encode()

    wheel = pathlib.Path(tmp) / "pip-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as out:
        for path, payload in files.items():
            out.writestr(path, payload)
    return wheel


def interior(wheel):
    with zipfile.ZipFile(wheel) as z:
        names = z.namelist()
        bom = {}
        if "pip/_vendor/bom.cdx.json" in names:
            bom = {
                c["name"]: c["version"]
                for c in json.loads(
                    z.read("pip/_vendor/bom.cdx.json"))["components"]
            }
        txt = {}
        for line in z.read("pip/_vendor/vendor.txt").decode().splitlines():
            s = line.strip()
            if "==" in s:
                txt[s.partition("==")[0]] = s.partition("==")[2]
        record = [
            line.split(",")[0]
            for line in z.read(f"{DIST_INFO}/RECORD").decode().splitlines()
            if line.strip()
        ]
    return names, bom, txt, record


def test_version_key_orders_numerically():
    assert hvs.version_key("26.10") > hvs.version_key("26.2")


def test_record_line_has_the_wheel_format():
    line = hvs.record_line("a/b.py", b"payload")
    path, digest, size = line.split(",")
    assert path == "a/b.py"
    assert digest.startswith("sha256=") and "=" not in digest[7:]
    assert size == str(len(b"payload"))


def test_code_version_in_wheel_reads_a_double_assignment():
    with tempfile.TemporaryDirectory() as tmp:
        wheel = build_wheel(
            tmp, declared=[("widget", "2.8.0", False)],
            bom={"widget": "2.8.0"}, code={"widget": "2.8.0"})
        with zipfile.ZipFile(wheel) as z:
            # urllib3 spells it "__version__ = version = '2.8.0'".
            assert hvs.code_version_in_wheel(z, "widget") == "2.8.0"


def test_code_version_in_wheel_ignores_a_re_export():
    # Regression: matching any quoted string on a line mentioning __version__
    # returned "__version__" from "from .data import __version__".
    with tempfile.TemporaryDirectory() as tmp:
        wheel = build_wheel(
            tmp, declared=[("widget", "1.0.0", False)],
            bom={"widget": "1.0.0"}, code={"widget": None})
        with zipfile.ZipFile(wheel) as z:
            assert hvs.code_version_in_wheel(z, "widget") is None


def test_interior_bom_is_reconciled_to_the_code():
    with tempfile.TemporaryDirectory() as tmp:
        wheel = build_wheel(
            tmp,
            declared=[("widget", "2.8.0", False)],
            bom={"widget": "2.7.0"},
            code={"widget": "2.8.0"},
            pkg_resources=False)
        assert hvs.reconcile_wheel_interior(wheel) is True
        _, bom, _, _ = interior(wheel)
        assert bom["widget"] == "2.8.0"


def test_pkg_resources_and_its_declaration_are_removed_together():
    with tempfile.TemporaryDirectory() as tmp:
        wheel = build_wheel(
            tmp,
            declared=[("widget", "1.0.0", False), ("setuptools", "70.3.0", False)],
            bom={"widget": "1.0.0", "setuptools": "70.3.0"},
            code={"widget": "1.0.0"})
        assert hvs.reconcile_wheel_interior(wheel) is True
        names, bom, txt, _ = interior(wheel)
        assert not any(n.startswith("pip/_vendor/pkg_resources/") for n in names)
        assert "setuptools" not in txt
        assert "setuptools" not in bom


def test_record_describes_only_files_the_wheel_contains():
    with tempfile.TemporaryDirectory() as tmp:
        wheel = build_wheel(
            tmp,
            declared=[("widget", "1.0.0", False), ("setuptools", "70.3.0", False)],
            bom={"widget": "1.0.0", "setuptools": "70.3.0"},
            code={"widget": "1.0.0"})
        hvs.reconcile_wheel_interior(wheel)
        names, _, _, record = interior(wheel)
        dangling = sorted(set(record) - set(names))
        assert dangling == [], f"RECORD references absent files: {dangling}"


def test_record_entry_for_an_already_absent_file_is_pruned():
    # RECORD is rebuilt from the surviving members, so a listing that was
    # already wrong on the way in does not survive untouched.
    with tempfile.TemporaryDirectory() as tmp:
        wheel = build_wheel(
            tmp,
            declared=[("widget", "2.8.0", False)],
            bom={"widget": "2.7.0"},
            code={"widget": "2.8.0"},
            pkg_resources=False,
            extra_record=["pip/_vendor/never_existed.py,sha256=abc,3"])
        hvs.reconcile_wheel_interior(wheel)
        _, _, _, record = interior(wheel)
        assert "pip/_vendor/never_existed.py" not in record


def test_changed_files_get_a_fresh_record_hash():
    with tempfile.TemporaryDirectory() as tmp:
        wheel = build_wheel(
            tmp,
            declared=[("widget", "2.8.0", False)],
            bom={"widget": "2.7.0"},
            code={"widget": "2.8.0"},
            pkg_resources=False)
        hvs.reconcile_wheel_interior(wheel)
        with zipfile.ZipFile(wheel) as z:
            payload = z.read("pip/_vendor/bom.cdx.json")
            expected = hvs.record_line("pip/_vendor/bom.cdx.json", payload)
            listed = [
                line for line in z.read(f"{DIST_INFO}/RECORD").decode().splitlines()
                if line.startswith("pip/_vendor/bom.cdx.json,")
            ]
        assert listed == [expected]


def test_a_wheel_with_no_bom_is_handled_and_none_is_invented():
    with tempfile.TemporaryDirectory() as tmp:
        wheel = build_wheel(
            tmp,
            declared=[("widget", "1.0.0", False)],
            bom={},
            code={"widget": "1.0.0"},
            omit_bom=True)
        hvs.reconcile_wheel_interior(wheel)
        with zipfile.ZipFile(wheel) as z:
            assert "pip/_vendor/bom.cdx.json" not in z.namelist()
            assert "pip/_vendor/vendor.txt" in z.namelist()


def test_a_consistent_wheel_is_left_alone():
    with tempfile.TemporaryDirectory() as tmp:
        wheel = build_wheel(
            tmp,
            declared=[("widget", "1.0.0", False)],
            bom={"widget": "1.0.0"},
            code={"widget": "1.0.0"},
            pkg_resources=False)
        before = wheel.read_bytes()
        assert hvs.reconcile_wheel_interior(wheel) is False
        assert wheel.read_bytes() == before


def test_a_wheel_without_a_record_is_refused():
    with tempfile.TemporaryDirectory() as tmp:
        wheel = pathlib.Path(tmp) / "pip-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as out:
            out.writestr("pip/_vendor/vendor.txt", "widget==1.0.0\n")
            out.writestr("pip/_vendor/bom.cdx.json", json.dumps(
                {"components": [{"name": "widget", "version": "0.1.0"}]}))
            out.writestr("pip/_vendor/widget/_version.py",
                         "__version__ = '1.0.0'\n")
        try:
            hvs.reconcile_wheel_interior(wheel)
        except SystemExit as exc:
            assert "RECORD" in str(exc)
        else:
            raise AssertionError(
                "repacking a wheel with no RECORD must not be silent")


# --- virtualenv's own inventory: the shipped CycloneDX SBOM and RECORD ---
#
# The fixtures are virtualenv's real SBOMs, trimmed: 21.15.2 identifies each
# bundled wheel as pkg:pypi/<name>@<version>, 21.15.7 and later as
# bundled:virtualenv/seed/wheels/embed/<wheel file>. Both schemes ship in
# released virtualenv versions, so both are tested.
#
# Each is virtualenv-<version>.dist-info/sboms/virtualenv.cdx.json from the
# PyPI wheel, with authors, supplier, description, licences and external
# references removed (personal names and non-ASCII text), metadata.tools and
# vendored entries cut to their identity fields, and each bundled wheel's file
# list cut to its first three entries. The dependency graph, compositions,
# formulation and every top-level and vendored component are kept whole.

TESTDATA = pathlib.Path(__file__).with_name("testdata")

SUPERSEDED = {
    "pip-26.0.1-py3-none-any.whl": None,
    "setuptools-82.0.1-py3-none-any.whl": None,
}


def fixture_path(version):
    # Not named *.cdx.json: source scanners (osv-scanner) read that suffix as
    # an inventory of this repository and would report the stale wheels the
    # fixture describes.
    return TESTDATA / f"virtualenv-{version}-sbom.fixture.json"


def load_fixture(version):
    return json.loads(fixture_path(version).read_text(encoding="ascii"))


def defined_refs(document):
    """Every bom-ref the document defines, at any depth."""
    found = set()

    def walk(components):
        for component in components or []:
            if component.get("bom-ref"):
                found.add(component["bom-ref"])
            walk(component.get("components"))

    metadata = document.get("metadata", {})
    if metadata.get("component", {}).get("bom-ref"):
        found.add(metadata["component"]["bom-ref"])
    tools = metadata.get("tools")
    if isinstance(tools, dict):
        walk(tools.get("components"))
    walk(document.get("components"))
    return found


def used_refs(document):
    """Every ref the dependency graph and compositions point at."""
    used = []
    for entry in document.get("dependencies", []):
        used.append(entry.get("ref"))
        used.extend(entry.get("dependsOn", []))
    for composition in document.get("compositions", []):
        used.extend(composition.get("assemblies", []))
        used.extend(composition.get("dependencies", []))
    return used


def dangling(document):
    defined = defined_refs(document)
    return sorted({ref for ref in used_refs(document) if ref not in defined})


def make_sbom_site(tmp, version):
    """A site-packages holding only virtualenv's dist-info with a real SBOM."""
    site = pathlib.Path(tmp) / "site"
    dist_info = site / f"virtualenv-{version}.dist-info"
    (dist_info / "sboms").mkdir(parents=True)
    (dist_info / "sboms" / "virtualenv.cdx.json").write_text(
        fixture_path(version).read_text(encoding="ascii"), encoding="utf-8")
    return site, dist_info


def removal_map(document):
    """removed wheel -> kept wheel, for the superseded pair in a fixture."""
    kept = {}
    for component in document["components"]:
        for prop in component.get("properties", []):
            if prop["name"] == "virtualenv:bundled-wheel":
                wheel = prop["value"].rsplit("/", 1)[-1]
                project = wheel.split("-", 1)[0]
                if wheel not in SUPERSEDED:
                    kept[project] = wheel
    return {removed: kept[removed.split("-", 1)[0]] for removed in SUPERSEDED}


def test_both_fixtures_resolve_before_any_rewrite():
    # The baseline the inventory tests rely on: virtualenv's own SBOM has no
    # dangling reference, so any found after a rewrite was made by the rewrite.
    for version in ("21.15.2", "21.15.8"):
        assert dangling(load_fixture(version)) == [], version


def test_removed_wheels_leave_no_reference_in_either_bom_ref_scheme():
    # Regression for #819: 21.15.7 moved bom-refs to bundled:<wheel path>, and
    # stale refs built only as pkg:pypi/<name>@<version> left 21 references
    # to the removed pip 26.0.1, so the build's own verify step exited 1.
    for version in ("21.15.2", "21.15.8"):
        with tempfile.TemporaryDirectory() as tmp:
            site, dist_info = make_sbom_site(tmp, version)
            sbom = dist_info / "sboms" / "virtualenv.cdx.json"
            replacements = removal_map(json.loads(sbom.read_text()))

            hvs.rewrite_inventory(site, replacements)

            document = json.loads(sbom.read_text())
            assert dangling(document) == [], (version, dangling(document))
            for ref in used_refs(document):
                for removed in replacements:
                    project, removed_version = removed.split("-", 2)[:2]
                    assert removed not in ref, (version, ref)
                    assert f"{project}@{removed_version}" not in ref, (version, ref)
            # The build step's own check, the one that failed in CI.
            hvs.verify(pathlib.Path(tmp) / "no-embed", site, replacements)


def test_removed_components_are_gone_and_kept_ones_are_untouched():
    for version in ("21.15.2", "21.15.8"):
        with tempfile.TemporaryDirectory() as tmp:
            site, dist_info = make_sbom_site(tmp, version)
            sbom = dist_info / "sboms" / "virtualenv.cdx.json"
            before = json.loads(sbom.read_text())
            replacements = removal_map(before)

            hvs.rewrite_inventory(site, replacements)

            after = json.loads(sbom.read_text())
            removed = {tuple(r.split("-", 2)[:2]) for r in replacements}
            assert not [c for c in after["components"]
                        if (c["name"], c.get("version")) in removed]
            kept_before = [c for c in before["components"]
                           if (c["name"], c.get("version")) not in removed]
            assert after["components"] == kept_before, version


# --- swapping in the distro's pip wheel, and describing what is on disk ---
#
# Each seed wheel is replaced by the distro's build of the same project in
# both directions: virtualenv 21.15.4 and later bundle pip 26.3, newer than
# Wolfi's patched 26.2.2, and keeping the newer PyPI copy left its vendored
# pkg_resources in every environment virtualenv created (#819, phase 2).

EMBED = "virtualenv/seed/wheels/embed"


def build_seed_wheel(directory, project, version, urllib3=None,
                     pkg_resources=False, marker=""):
    """A small wheel shaped like pip's or setuptools': METADATA, RECORD and,
    for pip, a vendored tree with vendor.txt."""
    dist = f"{project}-{version}.dist-info"
    files = {
        f"{project}/__init__.py": f"__version__ = '{version}'\n# {marker}\n".encode(),
        f"{dist}/METADATA": (
            "Metadata-Version: 2.4\n"
            f"Name: {project}\n"
            f"Version: {version}\n"
            f"Summary: synthetic {project} for tests\n"
            "Requires-Python: >=3.10\n"
            "Classifier: Programming Language :: Python :: 3\n"
            "Classifier: Programming Language :: Python :: 3 :: Only\n"
            "\n").encode(),
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    if urllib3 is not None:
        vendored = [f"urllib3=={urllib3}", "CacheControl==0.14.4"]
        if pkg_resources:
            vendored.append("setuptools==70.3.0")
        files[f"{project}/_vendor/vendor.txt"] = ("\n".join(vendored) + "\n").encode()
        files[f"{project}/_vendor/urllib3/_version.py"] = (
            f"__version__ = version = '{urllib3}'\n".encode())
        files[f"{project}/_vendor/cachecontrol/__init__.py"] = (
            b"__version__ = '0.14.4'\n")
    if pkg_resources:
        files[f"{project}/_vendor/pkg_resources/__init__.py"] = b"# setuptools code\n"
    record = [hvs.record_line(path, payload) for path, payload in files.items()]
    record.append(f"{dist}/RECORD,,")
    files[f"{dist}/RECORD"] = ("\n".join(record) + "\n").encode()

    wheel = pathlib.Path(directory) / f"{project}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as out:
        for path, payload in files.items():
            out.writestr(path, payload)
    return wheel


def sha256_file(path):
    import hashlib
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def bundle_tables(init):
    """BUNDLE_SUPPORT and BUNDLE_SHA256 as Python evaluates them."""
    import ast
    tables = {}
    for node in ast.parse(init.read_text(encoding="utf-8")).body:
        target = getattr(node, "target", None) or (
            node.targets[0] if isinstance(node, ast.Assign) else None)
        if isinstance(target, ast.Name) and target.id in (
                "BUNDLE_SUPPORT", "BUNDLE_SHA256"):
            tables[target.id] = ast.literal_eval(node.value)
    return tables["BUNDLE_SUPPORT"], tables["BUNDLE_SHA256"]


def make_seed_site(tmp, fixture, bundled_pip, distro_pip):
    """A site-packages after the superseded-wheel pass, plus a distro dir.

    bundled_pip and distro_pip are (version, urllib3 version, marker).
    Returns (site, embed, dist_info, distro_dir).
    """
    site = pathlib.Path(tmp) / "site"
    embed = site / EMBED
    embed.mkdir(parents=True)
    version, urllib3, marker = bundled_pip
    pip = build_seed_wheel(embed, "pip", version, urllib3=urllib3,
                           pkg_resources=True, marker=marker)
    setuptools = build_seed_wheel(embed, "setuptools", "84.2.1")

    names = [pip.name, setuptools.name]
    support = ",\n".join(
        f'    "{py}": {{"pip": "{pip.name}", "setuptools": "{setuptools.name}"}}'
        for py in ("3.12", "3.13"))
    digests = ",\n".join(
        f'    "{name}": "{sha256_file(embed / name)}"' for name in names)
    (embed / "__init__.py").write_text(
        "from __future__ import annotations\n\n"
        f"BUNDLE_SUPPORT: Final[dict[str, dict[str, str]]] = {{\n{support}\n}}\n"
        f"BUNDLE_SHA256: Final[dict[str, str]] = {{\n{digests}\n}}\n",
        encoding="utf-8")

    _, dist_info = make_sbom_site(tmp, fixture)
    sbom = dist_info / "sboms" / "virtualenv.cdx.json"
    hvs.rewrite_inventory(site, removal_map(json.loads(sbom.read_text())))
    # The fixture's pip entry describes the real PyPI wheel. The synthetic
    # wheel stands in for it, so at least the version has to agree.
    component = pip_component(json.loads(sbom.read_text()))
    assert component["version"] == version, (
        f"fixture {fixture} bundles pip {component['version']}")

    record_lines = [
        hvs.record_line(f"{EMBED}/{name}", (embed / name).read_bytes())
        for name in names
    ]
    record_lines.append(hvs.record_line(
        f"{EMBED}/__init__.py", (embed / "__init__.py").read_bytes()))
    record_lines.append(f"{EMBED}/__pycache__/__init__.cpython-313.pyc,,")
    record_lines.append(hvs.record_line(
        f"{dist_info.name}/sboms/virtualenv.cdx.json", sbom.read_bytes()))
    record_lines.append(f"{dist_info.name}/RECORD,,")
    (dist_info / "RECORD").write_text("\n".join(record_lines) + "\n",
                                      encoding="utf-8")

    distro_dir = pathlib.Path(tmp) / "distro"
    distro_dir.mkdir()
    version, urllib3, marker = distro_pip
    build_seed_wheel(distro_dir, "pip", version, urllib3=urllib3,
                     pkg_resources=True, marker=marker)
    return site, embed, dist_info, distro_dir


def run_swap(embed, distro_dir):
    saved = hvs.DISTRO_WHEELS
    hvs.DISTRO_WHEELS = distro_dir
    try:
        unmatched = hvs.prefer_distro_wheels(embed)
    finally:
        hvs.DISTRO_WHEELS = saved
    # main() re-measures RECORD once both passes are done.
    hvs.refresh_record(embed.parents[3], embed)
    return unmatched


def pip_component(document):
    found = [c for c in document["components"] if c["name"] == "pip"]
    assert len(found) == 1, [c.get("version") for c in found]
    return found[0]


def assert_inventory_describes(site, embed, dist_info, expected_wheel):
    """The SBOM, RECORD and BUNDLE tables describe exactly the wheel on disk."""
    on_disk = embed / expected_wheel
    digest = sha256_file(on_disk)
    project, version = expected_wheel.split("-", 2)[:2]

    support, sha = bundle_tables(embed / "__init__.py")
    assert sha[expected_wheel] == digest
    assert all(t["pip"] == expected_wheel for t in support.values()), support

    sbom = dist_info / "sboms" / "virtualenv.cdx.json"
    document = json.loads(sbom.read_text())
    component = pip_component(document)
    assert component["version"] == version
    assert component["purl"] == f"pkg:pypi/pip@{version}"
    assert component["hashes"] == [{"alg": "SHA-256", "content": digest}]
    wheel_props = [p["value"] for p in component["properties"]
                   if p["name"] == "virtualenv:bundled-wheel"]
    assert [v.rsplit("/", 1)[-1] for v in wheel_props] == [expected_wheel]
    ref = component["bom-ref"]
    assert ref in (f"bundled:{EMBED}/{expected_wheel}", f"pkg:pypi/pip@{version}"), ref

    with zipfile.ZipFile(on_disk) as z:
        members = {
            i.filename: z.read(i.filename) for i in z.infolist()
            if i.filename != f"{project}-{version}.dist-info/RECORD"
        }
    files = [c for c in component["components"] if c["type"] == "file"]
    assert {c["name"] for c in files} == set(members)
    for c in files:
        import hashlib
        assert c["hashes"][0]["content"] == hashlib.sha256(
            members[c["name"]]).hexdigest(), c["name"]
        assert c["bom-ref"] == f"{ref}#{c['name']}"
    vendored = [c for c in component["components"] if c["type"] != "file"]
    assert all(c["bom-ref"].startswith(f"{ref}#vendored/") for c in vendored)
    assert "setuptools" not in {c["name"] for c in vendored}
    own = [d for d in document["dependencies"] if d["ref"] == ref]
    assert len(own) == 1 and own[0]["dependsOn"] == [c["bom-ref"] for c in vendored]
    assert dangling(document) == [], dangling(document)

    record = (dist_info / "RECORD").read_text().splitlines()
    pip_lines = [line for line in record
                 if line.startswith(f"{EMBED}/pip-") and ".whl," in line]
    assert pip_lines == [
        hvs.record_line(f"{EMBED}/{expected_wheel}", on_disk.read_bytes())], pip_lines
    for path in (f"{EMBED}/__init__.py",
                 f"{dist_info.name}/sboms/virtualenv.cdx.json"):
        assert hvs.record_line(path, (site / path).read_bytes()) in record, path
    # The compiled __init__ is recreated when virtualenv is next imported (the
    # build's own seeded-environment check does that), so pip's line stays.
    assert f"{EMBED}/__pycache__/__init__.cpython-313.pyc,," in record, record
    return document


def test_distro_pip_replaces_a_newer_bundled_pip():
    # #819 phase 2: virtualenv bundles pip 26.3, Wolfi ships a patched 26.2.2.
    with tempfile.TemporaryDirectory() as tmp:
        site, embed, dist_info, distro = make_seed_site(
            tmp, "21.15.8", bundled_pip=("26.3", "2.7.0", "pypi"),
            distro_pip=("26.2.2", "2.8.0", "wolfi"))

        run_swap(embed, distro)

        assert sorted(p.name for p in embed.glob("*.whl")) == [
            "pip-26.2.2-py3-none-any.whl", "setuptools-84.2.1-py3-none-any.whl"]
        with zipfile.ZipFile(embed / "pip-26.2.2-py3-none-any.whl") as z:
            assert not [n for n in z.namelist() if "pkg_resources" in n]
        document = assert_inventory_describes(
            site, embed, dist_info, "pip-26.2.2-py3-none-any.whl")
        text = json.dumps(document)
        assert "pip-26.3-py3-none-any.whl" not in text
        assert "pip-26.3.dist-info" not in text
        assert "pip-26.3-py3-none-any.whl" not in (embed / "__init__.py").read_text()


def test_distro_pip_replaces_an_older_bundled_pip_in_the_pkg_pypi_scheme():
    with tempfile.TemporaryDirectory() as tmp:
        site, embed, dist_info, distro = make_seed_site(
            tmp, "21.15.2", bundled_pip=("26.2.2", "2.7.0", "pypi"),
            distro_pip=("26.3", "2.8.0", "wolfi"))

        run_swap(embed, distro)

        assert sorted(p.name for p in embed.glob("*.whl")) == [
            "pip-26.3-py3-none-any.whl", "setuptools-84.2.1-py3-none-any.whl"]
        document = assert_inventory_describes(
            site, embed, dist_info, "pip-26.3-py3-none-any.whl")
        assert pip_component(document)["bom-ref"] == "pkg:pypi/pip@26.3"
        assert "pkg:pypi/pip@26.2.2" not in json.dumps(document)


def test_same_version_distro_pip_is_described_by_its_own_hashes():
    # Same version, different bytes: the Wolfi build carries backports.
    with tempfile.TemporaryDirectory() as tmp:
        site, embed, dist_info, distro = make_seed_site(
            tmp, "21.15.2", bundled_pip=("26.2.2", "2.7.0", "pypi"),
            distro_pip=("26.2.2", "2.8.0", "wolfi"))
        sbom = dist_info / "sboms" / "virtualenv.cdx.json"
        declared = pip_component(json.loads(sbom.read_text()))["hashes"][0]["content"]

        run_swap(embed, distro)

        document = assert_inventory_describes(
            site, embed, dist_info, "pip-26.2.2-py3-none-any.whl")
        assert declared not in json.dumps(document)


# --- verify_inventory: the build's inventory-versus-disk gate ---

def described_site(tmp):
    """A swapped site whose whole inventory agrees with the synthetic wheels.

    The fixture's setuptools entry describes the real PyPI wheel, so it is
    pointed at the synthetic one first: its digest and its file entries. Its
    vendored entries stay, since the dependency graph refers to them.
    """
    import hashlib
    site, embed, dist_info, distro = make_seed_site(
        tmp, "21.15.8", bundled_pip=("26.3", "2.7.0", "pypi"),
        distro_pip=("26.2.2", "2.8.0", "wolfi"))
    sbom = dist_info / "sboms" / "virtualenv.cdx.json"
    document = json.loads(sbom.read_text())
    setuptools = embed / "setuptools-84.2.1-py3-none-any.whl"
    with zipfile.ZipFile(setuptools) as z:
        files = [
            {"type": "file", "name": i.filename,
             "hashes": [{"alg": "SHA-256",
                         "content": hashlib.sha256(z.read(i.filename)).hexdigest()}]}
            for i in z.infolist()
            if i.filename != "setuptools-84.2.1.dist-info/RECORD"
        ]
    for component in document["components"]:
        if component["name"] == "setuptools":
            component["hashes"] = [{"alg": "SHA-256", "content": sha256_file(setuptools)}]
            component["components"] = files + [
                c for c in component["components"] if c["type"] != "file"]
    sbom.write_text(json.dumps(document, indent=2) + "\n")
    run_swap(embed, distro)
    return site, embed, dist_info


def expect_refusal(site, embed, needle):
    try:
        hvs.verify_inventory(embed, site)
    except SystemExit as exc:
        assert needle in str(exc), str(exc)
    else:
        raise AssertionError(f"verify_inventory passed with a planted defect: {needle}")


def test_verify_inventory_passes_when_the_inventory_describes_the_disk():
    with tempfile.TemporaryDirectory() as tmp:
        site, embed, _ = described_site(tmp)
        hvs.verify_inventory(embed, site)


def test_verify_inventory_refuses_a_dangling_reference():
    with tempfile.TemporaryDirectory() as tmp:
        site, embed, dist_info = described_site(tmp)
        sbom = dist_info / "sboms" / "virtualenv.cdx.json"
        document = json.loads(sbom.read_text())
        document["dependencies"][0]["dependsOn"].append(
            f"bundled:{EMBED}/pip-26.3-py3-none-any.whl")
        sbom.write_text(json.dumps(document))
        expect_refusal(site, embed, "dangling reference")


def test_verify_inventory_refuses_an_sbom_hash_that_is_not_the_file():
    with tempfile.TemporaryDirectory() as tmp:
        site, embed, dist_info = described_site(tmp)
        sbom = dist_info / "sboms" / "virtualenv.cdx.json"
        document = json.loads(sbom.read_text())
        pip_component(document)["hashes"][0]["content"] = "0" * 64
        sbom.write_text(json.dumps(document))
        expect_refusal(site, embed, "SHA-256 is not the file's")


def test_verify_inventory_refuses_a_file_list_that_is_not_the_wheel():
    with tempfile.TemporaryDirectory() as tmp:
        site, embed, dist_info = described_site(tmp)
        sbom = dist_info / "sboms" / "virtualenv.cdx.json"
        document = json.loads(sbom.read_text())
        pip_component(document)["components"].append({
            "type": "file", "name": "pip/_vendor/pkg_resources/__init__.py",
            "hashes": [{"alg": "SHA-256", "content": "0" * 64}]})
        sbom.write_text(json.dumps(document))
        expect_refusal(site, embed, "file entries do not match")


def test_verify_inventory_refuses_a_stale_record_line():
    with tempfile.TemporaryDirectory() as tmp:
        site, embed, dist_info = described_site(tmp)
        record = dist_info / "RECORD"
        record.write_text(record.read_text().replace(
            "pip-26.2.2-py3-none-any.whl,sha256=", "pip-26.2.2-py3-none-any.whl,sha256=X"))
        expect_refusal(site, embed, "RECORD does not list pip-26.2.2")


def test_verify_inventory_refuses_an_undeclared_wheel_and_a_wrong_digest():
    with tempfile.TemporaryDirectory() as tmp:
        site, embed, _ = described_site(tmp)
        build_seed_wheel(embed, "wheel", "0.46.3")
        expect_refusal(site, embed, "0 entries for wheel-0.46.3-py3-none-any.whl")
    with tempfile.TemporaryDirectory() as tmp:
        site, embed, _ = described_site(tmp)
        init = embed / "__init__.py"
        digest = sha256_file(embed / "pip-26.2.2-py3-none-any.whl")
        init.write_text(init.read_text().replace(digest, "1" * 64))
        expect_refusal(site, embed, "BUNDLE_SHA256 does not hold the digest of pip-26.2.2")


def rewrite_sbom(dist_info, change):
    sbom = dist_info / "sboms" / "virtualenv.cdx.json"
    document = json.loads(sbom.read_text())
    change(document)
    sbom.write_text(json.dumps(document))


def test_verify_inventory_refuses_a_stale_vendored_entry():
    # Comparing only file entries would pass a vendored urllib3 2.7.0 next to
    # a wheel that vendors 2.8.0.
    with tempfile.TemporaryDirectory() as tmp:
        site, embed, dist_info = described_site(tmp)

        def stale(document):
            for nested in pip_component(document)["components"]:
                if nested.get("name") == "urllib3":
                    nested["version"] = "2.7.0"
                    nested["purl"] = "pkg:pypi/urllib3@2.7.0"
        rewrite_sbom(dist_info, stale)
        expect_refusal(site, embed, "vendored entries do not match")


def test_verify_inventory_refuses_a_re_added_vendored_package():
    with tempfile.TemporaryDirectory() as tmp:
        site, embed, dist_info = described_site(tmp)

        def readd(document):
            component = pip_component(document)
            component["components"].append({
                "type": "library", "name": "setuptools", "version": "70.3.0",
                "purl": "pkg:pypi/setuptools@70.3.0",
                "bom-ref": component["bom-ref"] + "#vendored/pkg:pypi/setuptools@70.3.0",
                "properties": [{"name": "virtualenv:vendored-manifest",
                                "value": "pip/_vendor/vendor.txt"}]})
        rewrite_sbom(dist_info, readd)
        expect_refusal(site, embed, "vendored entries do not match")


def test_verify_inventory_refuses_an_extra_seed_project_component():
    with tempfile.TemporaryDirectory() as tmp:
        site, embed, dist_info = described_site(tmp)
        rewrite_sbom(dist_info, lambda d: d["components"].append(
            {"type": "library", "name": "pip", "version": "26.3",
             "purl": "pkg:pypi/pip@26.3"}))
        expect_refusal(site, embed, "pip 26.3")


def test_verify_inventory_refuses_a_purl_naming_another_version():
    with tempfile.TemporaryDirectory() as tmp:
        site, embed, dist_info = described_site(tmp)

        def wrong(document):
            pip_component(document)["purl"] = "pkg:pypi/pip@26.3"
        rewrite_sbom(dist_info, wrong)
        expect_refusal(site, embed, "purl")


def test_verify_inventory_refuses_stale_record_lines_for_rewritten_files():
    for target in ("__init__.py", "sboms/virtualenv.cdx.json"):
        with tempfile.TemporaryDirectory() as tmp:
            site, embed, dist_info = described_site(tmp)
            record = dist_info / "RECORD"
            lines = []
            for line in record.read_text().splitlines():
                if line.split(",")[0].endswith(target):
                    line = line.replace(",sha256=", ",sha256=X", 1)
                lines.append(line)
            record.write_text("\n".join(lines) + "\n")
            expect_refusal(site, embed, "RECORD does not list")


def test_vendored_entries_without_a_manifest_are_refused_not_dropped():
    # An upstream rename of the vendored-manifest property must not make
    # describe_component drop every vendored entry silently.
    with tempfile.TemporaryDirectory() as tmp:
        wheel = build_seed_wheel(tmp, "pip", "26.2.2", urllib3="2.8.0")
        component = {
            "bom-ref": f"bundled:{EMBED}/pip-26.3-py3-none-any.whl",
            "name": "pip", "version": "26.3", "components": [
                {"type": "library", "name": "urllib3", "version": "2.7.0",
                 "properties": [{"name": "virtualenv:renamed-manifest",
                                 "value": "pip/_vendor/vendor.txt"}]}]}
        try:
            hvs.describe_component(component, "pip-26.3-py3-none-any.whl", wheel)
        except SystemExit as exc:
            assert "manifest" in str(exc), str(exc)
        else:
            raise AssertionError("vendored entries with no manifest were dropped silently")


def test_a_component_with_an_unknown_bom_ref_scheme_is_refused():
    with tempfile.TemporaryDirectory() as tmp:
        wheel = build_seed_wheel(tmp, "pip", "26.2.2", urllib3="2.8.0")
        component = {"bom-ref": "urn:uuid:1234", "name": "pip", "version": "26.3"}
        try:
            hvs.describe_component(component, "pip-26.3-py3-none-any.whl", wheel)
        except SystemExit as exc:
            assert "refusing to guess" in str(exc)
        else:
            raise AssertionError("an unrecognised bom-ref was renamed by guesswork")


if __name__ == "__main__":
    # Runnable without pytest, so CI needs no extra dependency.
    # Every test runs and every failure is named, so one red test does not
    # hide whether the others pass.
    import traceback
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    failed = []
    for name, fn in tests:
        try:
            fn()
        except (Exception, SystemExit):  # the script exits on refusal; Ctrl-C still stops
            failed.append(name)
            print(f"FAIL {name}")
            traceback.print_exc()
        else:
            print(f"ok   {name}")
    print(f"{len(tests) - len(failed)} passed, {len(failed)} failed")
    if failed:
        print("failed: " + ", ".join(failed))
        sys.exit(1)
