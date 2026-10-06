"""Unit tests for the declaration reconciliation in harden-pip-vendor.py.

Hermetic: every fixture is a synthetic vendor directory in a temporary path,
so these run without Docker, without a network and without a built image.

The vendored package names are deliberately fictional. code_version() asks the
interpreter to import pip._vendor.<name> before falling back to reading the
sources, so a real name such as urllib3 would resolve against whatever pip is
installed on the machine running the tests and the fixture would be ignored.
"""

import importlib.util
import json
import pathlib
import sys
import tempfile

_spec = importlib.util.spec_from_file_location(
    "harden_pip_vendor", pathlib.Path(__file__).with_name("harden-pip-vendor.py"))
hpv = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = hpv
_spec.loader.exec_module(hpv)


def build_vendor(tmp, declared, bom, code):
    """Create a synthetic pip/_vendor tree.

    declared: list of (name, version, indented) for vendor.txt
    bom:      dict name -> version for bom.cdx.json (omit a name to leave it out)
    code:     dict name -> version or None, written into the package sources
    """
    vendor = pathlib.Path(tmp) / "_vendor"
    vendor.mkdir(parents=True)

    lines = []
    for name, version, indented in declared:
        prefix = "    " if indented else ""
        lines.append(f"{prefix}{name}=={version}")
    (vendor / "vendor.txt").write_text("\n".join(lines) + "\n")

    components = []
    for name, version in bom.items():
        components.append({
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name}@{version}",
        })
    (vendor / "bom.cdx.json").write_text(
        json.dumps({"components": components}, indent=2) + "\n")

    for name, version in code.items():
        package = vendor / name.replace("-", "_")
        package.mkdir()
        if version is None:
            # A package whose version cannot be read from its sources.
            (package / "__init__.py").write_text("from .data import __version__\n")
        else:
            (package / "_version.py").write_text(f'__version__ = "{version}"\n')
    return vendor


def read_bom(vendor):
    return {
        c["name"]: c["version"]
        for c in json.loads((vendor / "bom.cdx.json").read_text())["components"]
    }


def read_vendor_txt(vendor):
    out = {}
    for line in (vendor / "vendor.txt").read_text().splitlines():
        s = line.strip()
        if "==" in s:
            out[s.partition("==")[0]] = s.partition("==")[2]
    return out


def test_normalize_version_ignores_zero_padding():
    assert hpv.normalize_version("2026.06.17") == hpv.normalize_version("2026.6.17")


def test_normalize_version_orders_numerically():
    assert hpv.normalize_version("26.10") > hpv.normalize_version("26.2")


def test_declared_versions_reads_indented_entries():
    with tempfile.TemporaryDirectory() as tmp:
        vendor = build_vendor(
            tmp,
            declared=[("widget", "1.2.3", False), ("sprocket", "3.1.0", True)],
            bom={}, code={})
        got = hpv.declared_versions(vendor)
        # An anchored match would miss the indented entry entirely.
        assert got == {"widget": "1.2.3", "sprocket": "3.1.0"}


def test_bom_versions_skips_components_with_no_version():
    with tempfile.TemporaryDirectory() as tmp:
        vendor = build_vendor(tmp, declared=[], bom={}, code={})
        (vendor / "bom.cdx.json").write_text(json.dumps({"components": [
            {"name": "pip", "version": ""},
            {"name": "widget", "version": "1.2.3"},
        ]}) + "\n")
        assert hpv.bom_versions(vendor) == {"widget": "1.2.3"}


def test_reconcile_raises_a_bom_that_is_behind_the_code():
    with tempfile.TemporaryDirectory() as tmp:
        vendor = build_vendor(
            tmp,
            declared=[("widget", "2.8.0", False)],
            bom={"widget": "2.7.0"},
            code={"widget": "2.8.0"})
        hpv.reconcile_declarations(vendor)
        assert read_bom(vendor)["widget"] == "2.8.0"


def test_reconcile_lowers_a_bom_that_is_ahead_of_the_code():
    # The dangerous direction: a declaration claiming something newer than the
    # code understates risk, so it must be corrected downwards too.
    with tempfile.TemporaryDirectory() as tmp:
        vendor = build_vendor(
            tmp,
            declared=[("widget", "3.15", False)],
            bom={"widget": "3.18"},
            code={"widget": "3.15"})
        hpv.reconcile_declarations(vendor)
        assert read_bom(vendor)["widget"] == "3.15"


def test_reconcile_corrects_the_bom_even_when_vendor_txt_agrees():
    # Regression: an earlier revision iterated only the names vendor.txt
    # declares and compared only against vendor.txt, so a BOM that disagreed
    # on its own was never looked at.
    with tempfile.TemporaryDirectory() as tmp:
        vendor = build_vendor(
            tmp,
            declared=[("widget", "1.2.1", False)],
            bom={"widget": "1.1.2"},
            code={"widget": "1.2.1"})
        hpv.reconcile_declarations(vendor)
        assert read_bom(vendor)["widget"] == "1.2.1"
        assert read_vendor_txt(vendor)["widget"] == "1.2.1"


def test_reconcile_updates_the_purl_with_the_version():
    with tempfile.TemporaryDirectory() as tmp:
        vendor = build_vendor(
            tmp,
            declared=[("widget", "2.8.0", False)],
            bom={"widget": "2.7.0"},
            code={"widget": "2.8.0"})
        hpv.reconcile_declarations(vendor)
        purl = json.loads(
            (vendor / "bom.cdx.json").read_text())["components"][0]["purl"]
        assert purl == "pkg:pypi/widget@2.8.0"


def test_reconcile_preserves_indentation_in_vendor_txt():
    with tempfile.TemporaryDirectory() as tmp:
        vendor = build_vendor(
            tmp,
            declared=[("sprocket", "1.0.0", True)],
            bom={"sprocket": "0.9.0"},
            code={"sprocket": "2.0.0"})
        hpv.reconcile_declarations(vendor)
        text = (vendor / "vendor.txt").read_text()
        assert text == "    sprocket==2.0.0\n"


def test_reconcile_leaves_padding_only_differences_alone():
    with tempfile.TemporaryDirectory() as tmp:
        vendor = build_vendor(
            tmp,
            declared=[("widget", "2026.6.17", False)],
            bom={"widget": "2026.6.17"},
            code={"widget": "2026.06.17"})
        before = (vendor / "vendor.txt").read_text()
        hpv.reconcile_declarations(vendor)
        # Same version, different spelling: rewriting would churn every build.
        assert (vendor / "vendor.txt").read_text() == before
        assert read_bom(vendor)["widget"] == "2026.6.17"


def test_verify_passes_when_declarations_match_the_code():
    with tempfile.TemporaryDirectory() as tmp:
        vendor = build_vendor(
            tmp,
            declared=[("widget", "1.0.0", False)],
            bom={"widget": "1.0.0"},
            code={"widget": "1.0.0"})
        hpv.verify_declarations(vendor)


def test_verify_refuses_a_stale_bom():
    with tempfile.TemporaryDirectory() as tmp:
        vendor = build_vendor(
            tmp,
            declared=[("widget", "1.0.0", False)],
            bom={"widget": "0.1.0"},
            code={"widget": "1.0.0"})
        try:
            hpv.verify_declarations(vendor)
        except SystemExit as exc:
            assert "bom.cdx.json" in str(exc) and "widget" in str(exc)
        else:
            raise AssertionError("a stale bom.cdx.json must fail the build")


def test_verify_refuses_a_stale_vendor_txt():
    with tempfile.TemporaryDirectory() as tmp:
        vendor = build_vendor(
            tmp,
            declared=[("widget", "0.1.0", False)],
            bom={"widget": "1.0.0"},
            code={"widget": "1.0.0"})
        try:
            hpv.verify_declarations(vendor)
        except SystemExit as exc:
            assert "vendor.txt" in str(exc)
        else:
            raise AssertionError("a stale vendor.txt must fail the build")


def test_verify_refuses_to_report_success_having_checked_nothing():
    # A vacuous pass read as a verified one is the failure this guards against.
    with tempfile.TemporaryDirectory() as tmp:
        vendor = build_vendor(
            tmp,
            declared=[("widget", "1.0.0", False)],
            bom={"widget": "1.0.0"},
            code={"widget": None})
        try:
            hpv.verify_declarations(vendor)
        except SystemExit as exc:
            assert "nothing was verified" in str(exc)
        else:
            raise AssertionError("verifying zero packages must not pass")


if __name__ == "__main__":
    # Runnable without pytest, so CI needs no extra dependency.
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    for name, fn in tests:
        fn()
        print(f"ok   {name}")
    print(f"{len(tests)} passed")
