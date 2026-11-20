"""Unit tests for pr-gate.py: the pull request's required build checks.

Hermetic: the job listing is synthetic, no network, no GitHub API.

Run with: python3 scripts/test_pr_gate.py
"""

import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tempfile

_spec = importlib.util.spec_from_file_location(
    "pr_gate", pathlib.Path(__file__).with_name("pr-gate.py"))
pg = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = pg
_spec.loader.exec_module(pg)

AMD, ARM = "linux/amd64", "linux/arm64"


def leg(image, platform, conclusion="success", status="completed"):
    return {"name": f"publish_image ({image}, {platform})", "status": status,
            "conclusion": conclusion}


def judge(jobs, platform, images, red=()):
    return pg.evaluate(jobs, platform, list(images), list(red), log=io.StringIO())


def test_every_selected_leg_succeeding_passes():
    jobs = [leg("a", AMD), leg("a", ARM), leg("b", AMD), leg("b", ARM)]
    assert judge(jobs, AMD, ["a", "b"]) is True
    assert judge(jobs, ARM, ["a", "b"]) is True


def test_one_failed_leg_fails_its_platform_only():
    jobs = [leg("a", AMD), leg("a", ARM, "failure"), leg("b", AMD), leg("b", ARM)]
    assert judge(jobs, ARM, ["a", "b"]) is False
    assert judge(jobs, AMD, ["a", "b"]) is True


def test_a_failed_leg_of_an_image_already_red_on_main_does_not_gate():
    jobs = [leg("a", AMD, "failure"), leg("b", AMD)]
    assert judge(jobs, AMD, ["a", "b"], red=["a"]) is True
    # Only that image: another image's failure still fails.
    jobs = [leg("a", AMD), leg("b", AMD, "failure")]
    assert judge(jobs, AMD, ["a", "b"], red=["a"]) is False


def test_cancelled_timed_out_skipped_or_unfinished_legs_always_fail():
    for conclusion, status in (("cancelled", "completed"), ("timed_out", "completed"),
                               ("skipped", "completed"), (None, "in_progress"),
                               ("action_required", "completed"), ("neutral", "completed")):
        jobs = [leg("a", AMD, conclusion, status)]
        assert judge(jobs, AMD, ["a"]) is False, (conclusion, status)
        # Not even for an image already red: only a plain failure is excused.
        assert judge(jobs, AMD, ["a"], red=["a"]) is False, (conclusion, status)


def test_a_missing_or_duplicated_leg_fails():
    assert judge([leg("a", AMD)], AMD, ["a", "b"]) is False
    assert judge([leg("a", AMD), leg("a", AMD)], AMD, ["a"]) is False
    assert judge([], AMD, ["a"]) is False


def test_nothing_selected_needs_the_one_reporting_leg():
    no_image = {"name": f"publish_image (no image changed, {AMD})", "status": "completed",
                "conclusion": "success"}
    assert judge([no_image], AMD, [""]) is True
    assert judge([], AMD, [""]) is False
    assert judge([dict(no_image, conclusion="failure")], AMD, [""]) is False


def test_a_leg_carrying_a_required_name_is_ignored_not_counted():
    # A dispatch on the branch, or a mistake, must never satisfy the gate.
    impostor = {"name": f"publish_image ({AMD})", "status": "completed", "conclusion": "success"}
    assert judge([impostor], AMD, ["a"]) is False


def run_cli(listing, platform, images, red):
    script = pathlib.Path(__file__).with_name("pr-gate.py")
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "jobs.json"
        path.write_text(listing if isinstance(listing, str) else json.dumps(listing))
        done = subprocess.run([sys.executable, "-B", str(script), str(path), platform, images, red],
                              capture_output=True, text=True, timeout=30, check=False)
    return done.returncode, done.stdout + done.stderr


def test_cli_passes_fails_and_refuses_bad_input():
    ok = {"total_count": 2, "jobs": [leg("a", AMD), leg("a", ARM)]}
    assert run_cli(ok, AMD, '["a"]', "[]")[0] == 0
    bad = {"total_count": 1, "jobs": [leg("a", AMD, "failure")]}
    rc, out = run_cli(bad, AMD, '["a"]', "[]")
    assert rc == 1 and "::error::" in out, out
    rc, out = run_cli(bad, AMD, '["a"]', '["a"]')
    assert rc == 0 and "::warning::" in out, out
    # A listing longer than one page could hide a failed leg: refused.
    paged = {"total_count": 101, "jobs": [leg("a", AMD)]}
    assert run_cli(paged, AMD, '["a"]', "[]")[0] == 2
    for images, red in (('["A"]', "[]"), ('["a"]', '["../x"]'), ("a", "[]"), ('["a",""]', "[]"),
                        ('[1]', "[]"), ('["a"]', "{}"), ('["a!"]', "[]"), ('["ab\\n"]', "[]"),
                        ('["a..b"]', "[]"), (json.dumps(["a" * 65]), "[]"), ('["a"]', '["b c"]')):
        assert run_cli(ok, AMD, images, red)[0] == 2, (images, red)
    # 64 characters is still a valid name: judged (no leg for it, so fail), not refused.
    assert run_cli(ok, AMD, json.dumps(["a" * 64]), "[]")[0] == 1
    assert run_cli("<html>", AMD, '["a"]', "[]")[0] == 2
    # Without a count the listing cannot be shown to be complete.
    assert run_cli({"jobs": [leg("a", AMD)]}, AMD, '["a"]', "[]")[0] == 2
    assert run_cli(ok, "linux/s390x", '["a"]', "[]")[0] == 2


if __name__ == "__main__":
    import traceback
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    failed = []
    for name, fn in tests:
        try:
            fn()
        # SystemExit counts as a failure (an exit inside a test must not end
        # the run as if it passed); Ctrl-C still stops the run.
        except (Exception, SystemExit):
            failed.append(name)
            print(f"FAIL {name}")
            traceback.print_exc()
        else:
            print(f"ok   {name}")
    print(f"{len(tests) - len(failed)} passed, {len(failed)} failed")
    if failed:
        sys.exit(1)
