"""Unit tests for the seed wheel hardening in harden-virtualenv-seeds.py.

Hermetic: each fixture is a synthetic wheel built in a temporary directory, so
these run without Docker, without a network and without a built image.

Only the parts that operate on a wheel are covered here. prefer_distro_wheels
and verify_seeded_environment need a real interpreter tree and a distro wheel
directory, so they are exercised by the image build instead, which fails
closed if they misbehave.
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


if __name__ == "__main__":
    # Runnable without pytest, so CI needs no extra dependency.
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    for name, fn in tests:
        fn()
        print(f"ok   {name}")
    print(f"{len(tests)} passed")
