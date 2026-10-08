"""Unit tests for publish-report.py (no network: gh and docker are replaced)."""

import argparse
import importlib.util
import pathlib
import sys
import tempfile

_spec = importlib.util.spec_from_file_location(
    "publish_report", pathlib.Path(__file__).with_name("publish-report.py"))
pr = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = pr
_spec.loader.exec_module(pr)

# Shaped like the gate's real table output on python-base v1.1.499, which
# failed with "Total: 3 (MEDIUM: 1, HIGH: 2, CRITICAL: 0)" on each architecture.
# Trivy draws its tables with box-drawing characters; plain ASCII stands in.
TRIVY_FINDINGS = """
Report Summary

| Target                                  | Type      | Vulnerabilities |
| python-base-linux-amd64:test (wolfi)    | wolfi     | 0               |
| home/nonroot/.local/lib/.../pip/_vendor | python-pkg| 3               |

python-base-linux-amd64:test (wolfi)
Total: 0 (MEDIUM: 0, HIGH: 0, CRITICAL: 0)

Python (python-pkg)
Total: 3 (MEDIUM: 1, HIGH: 2, CRITICAL: 0)
| urllib3 | CVE-2026-00001 | HIGH | 2.7.0 | 2.8.0 |
"""
TRIVY_FATAL = "2026-10-06T17:22:05Z\tFATAL\tFatal error\trun error: image scan error: timeout\n"


# ---------------------------------------------------------------------------
# Pure decisions
# ---------------------------------------------------------------------------

def test_release_tag_is_parsed_and_anything_else_rejected():
    assert pr.parse_tag("release/go-base-1.27/v0.0.33") == ("go-base-1.27", "v0.0.33")
    for bad in ("refs/tags/release/x/v1.0.0", "release/x/1.0.0", "release/x/v1.0"):
        try:
            pr.parse_tag(bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted {bad}")


def test_newest_release_is_by_version_and_per_image():
    tags = ["release/go-base/v1.0.9", "release/go-base/v1.0.10", "release/go-base/v1.0.2",
            "release/go-base-1.27/v9.9.9", "release/go-base/v1.0.10-rc1"]
    assert pr.newest_release(tags, "go-base") == "release/go-base/v1.0.10"
    assert pr.newest_release(tags, "go-base-1.27") == "release/go-base-1.27/v9.9.9"
    assert pr.newest_release(tags, "wolfi-base") is None


def test_findings_are_summed_across_targets():
    assert pr.count_findings(TRIVY_FINDINGS) == 3
    assert pr.count_findings("no table at all") == 0


def test_fatal_output_is_a_scan_that_did_not_run():
    assert pr.scan_failed_to_run(TRIVY_FATAL)
    assert not pr.scan_failed_to_run(TRIVY_FINDINGS)


def test_failed_steps_lists_each_failed_step_and_bare_failed_jobs():
    jobs = [
        {"name": "publish_image (linux/amd64)", "conclusion": "failure",
         "steps": [{"name": "Build", "conclusion": "success"},
                   {"name": "Run Trivy vulnerability scanner for linux/amd64", "conclusion": "failure"}]},
        {"name": "create_release", "conclusion": "timed_out", "steps": []},
        {"name": "publish_image (linux/arm64)", "conclusion": "success", "steps": []},
        {"name": "report_publish_result", "conclusion": None, "steps": []},
    ]
    assert pr.failed_steps(jobs) == [
        ("publish_image (linux/amd64)", "Run Trivy vulnerability scanner for linux/amd64"),
        ("create_release", ""),
    ]


TRIVY_STEP = [("publish_image (linux/amd64)", "Run Trivy vulnerability scanner for linux/amd64")]


def test_trivy_findings_are_counted_in_the_reason():
    assert pr.classify(TRIVY_STEP, [TRIVY_FINDINGS, TRIVY_FINDINGS]) == \
        "Trivy gate: 6 fixable MEDIUM+ findings"
    one = TRIVY_FINDINGS.replace("Total: 3", "Total: 1")
    assert pr.classify(TRIVY_STEP, [one]) == "Trivy gate: 1 fixable MEDIUM+ finding"


def test_a_scan_that_could_not_run_is_not_reported_as_findings():
    assert pr.classify(TRIVY_STEP, [TRIVY_FATAL, TRIVY_FINDINGS]) == "Trivy could not scan the image"


def test_a_non_cve_failure_never_gets_a_cve_count():
    # The defect to avoid: "blocked by 0 fixable MEDIUM+ findings".
    reasons = [
        pr.classify(TRIVY_STEP, ["Report Summary\n"]),
        pr.classify([("publish_image (linux/arm64)", "Run Container Structure Tests for linux/arm64")], []),
        pr.classify([("publish_image (linux/amd64)", "Sign container image with Cosign")], []),
        pr.classify([("create_multiarch_manifests", "")], []),
        pr.classify([], []),
    ]
    assert reasons == ["Trivy gate failed", "container structure tests failed",
                       "Sign container image with Cosign failed",
                       "create_multiarch_manifests failed", "publish did not complete"]
    assert not any("0 fixable" in r or "finding" in r for r in reasons)


def test_issue_title_and_matching_do_not_confuse_similar_images():
    title = pr.failure_title("go-base", "v1.0.531", "Trivy gate failed")
    assert title == "Publish failed: go-base v1.0.531 - Trivy gate failed"
    assert pr.is_issue_for(title, "go-base")
    assert not pr.is_issue_for(pr.failure_title("go-base-1.27", "v0.0.34", "x"), "go-base")


def test_body_carries_the_run_the_steps_and_the_gate_output_truncated():
    gate = {"linux-amd64": {"trivy": TRIVY_FINDINGS + "x" * (pr.MAX_SECTION + 10),
                            "structure-tests": "FAIL: python3 is on PATH"}}
    body = pr.failure_body("release/python-base/v1.1.506", "https://run/1", TRIVY_STEP, gate)
    assert "https://run/1" in body and "release/python-base/v1.1.506" in body
    assert "Run Trivy vulnerability scanner for linux/amd64" in body
    assert "Total: 3" in body and "truncated" in body
    assert "FAIL: python3 is on PATH" in body
    assert len(body) < 65536


def test_guard_outputs_are_carried_without_naming_them():
    gate = {"linux-arm64": {"check-virtualenv-seeds": "::error::pip has 2 seed wheels"}}
    body = pr.failure_body("release/python-base/v1.1.509", "u", [], gate)
    assert "check-virtualenv-seeds output, linux-arm64" in body
    assert "pip has 2 seed wheels" in body


def test_stale_reason_covers_every_outcome():
    latest_old = {"amd64": "v1.1.493", "arm64": "v1.1.493", "multi-arch": "v1.1.493"}
    tag = "release/python-base/v1.1.499"
    fresh = {"amd64": "v1.1.499", "arm64": "v1.1.499", "multi-arch": "v1.1.499"}
    assert pr.stale_reason("python-base", tag, fresh, None) is None
    assert pr.stale_reason("python-base", None, latest_old, None) is None
    assert pr.stale_reason("python-base", tag, latest_old, {"status": "in_progress"}) is None
    assert "never started a publish" in pr.stale_reason("python-base", tag, latest_old, None)
    failed = pr.stale_reason("python-base", tag, latest_old,
                             {"status": "completed", "conclusion": "failure", "html_url": "https://run/9"})
    assert "ended `failure`" in failed and "https://run/9" in failed and "v1.1.493" in failed
    landed = pr.stale_reason("python-base", tag, latest_old,
                             {"status": "completed", "conclusion": "success", "html_url": "u"})
    assert "published successfully but" in landed


def test_only_the_multi_arch_tag_being_behind_is_still_stale():
    tag = "release/nginx-base/v1.1.600"
    latest = {"amd64": "v1.1.600", "arm64": "v1.1.600", "multi-arch": "v1.1.599"}
    reason = pr.stale_reason("nginx-base", tag, latest,
                             {"status": "completed", "conclusion": "failure", "html_url": "u"})
    assert reason and "multi-arch v1.1.599" in reason


def test_an_unreadable_latest_is_reported_not_treated_as_current():
    reason = pr.stale_reason("x", "release/x/v1.0.1", {"amd64": None}, None)
    assert reason and "unreadable" in reason


def test_version_label_reads_single_images_and_indexes():
    single = {"config": {"Labels": {"org.opencontainers.image.version": "v1.1.505"}}}
    index = {"unknown/unknown": {"config": {"Labels": {}}},
             "linux/amd64": {"config": {"Labels": {"org.opencontainers.image.version": "v2.0.0"}}}}
    assert pr.version_label(single) == "v1.1.505"
    assert pr.version_label(index) == "v2.0.0"
    assert pr.version_label({}) is None


def test_gate_reports_are_read_per_platform():
    root = pathlib.Path(tempfile.mkdtemp())
    (root / "linux-amd64").mkdir()
    (root / "linux-amd64" / "trivy.txt").write_text(TRIVY_FINDINGS)
    (root / "linux-arm64").mkdir()
    (root / "linux-arm64" / "structure-tests.txt").write_text("PASS")
    gate = pr.read_gate(root)
    assert set(gate) == {"linux-amd64", "linux-arm64"}
    assert gate["linux-amd64"]["trivy"] == TRIVY_FINDINGS
    assert gate["linux-arm64"] == {"structure-tests": "PASS"}
    assert pr.read_gate(root / "missing") == {}


# ---------------------------------------------------------------------------
# Commands, with GitHub replaced by recorders
# ---------------------------------------------------------------------------

class FakeGitHub:
    def __init__(self, tags=(), issue=None, jobs=()):
        self.tags, self.issue, self.jobs, self.calls = list(tags), issue, list(jobs), []

    def install(self):
        self.saved = {n: getattr(pr, n) for n in
                      ("release_tags", "open_issue", "run_jobs", "run", "ensure_label")}
        pr.release_tags = lambda repo, image: self.tags
        pr.open_issue = lambda repo, label, match: (
            self.issue if self.issue and match(self.issue["title"]) else None)
        pr.run_jobs = lambda repo, run_id: self.jobs
        pr.run = lambda *cmd, stdin=None: self.calls.append((cmd, stdin)) or ""
        pr.ensure_label = lambda *a: self.calls.append((("label",) + a, None))
        return self

    def restore(self):
        for name, fn in self.saved.items():
            setattr(pr, name, fn)

    def verbs(self):
        return [c[0][2] if c[0][0] == "gh" else c[0][0] for c in self.calls]


def publish(fake, tag, outcome, gate_dir="/nonexistent"):
    fake.install()
    try:
        return pr.cmd_publish(argparse.Namespace(
            repo="o/r", tag=tag, run_id="1", run_url="https://run/1", outcome=outcome,
            gate_dir=gate_dir))
    finally:
        fake.restore()


TAGS = ["release/python-base/v1.1.505", "release/python-base/v1.1.506"]
FAILED_JOBS = [{"name": "publish_image (linux/amd64)", "conclusion": "failure",
                "steps": [{"name": "Run Trivy vulnerability scanner for linux/amd64",
                           "conclusion": "failure"}]}]


def test_a_rerun_of_an_older_tag_changes_no_issue():
    # The other defect to avoid: an old tree re-run can never pass.
    fake = FakeGitHub(TAGS, issue={"number": 7, "title": "Publish failed: python-base v1.1.505 - x"},
                      jobs=FAILED_JOBS)
    for outcome in ("failure", "success"):
        assert publish(fake, "release/python-base/v1.1.505", outcome) == 0
    assert fake.calls == []


def test_a_failed_newest_release_opens_an_issue_with_the_real_reason():
    fake = FakeGitHub(TAGS, jobs=FAILED_JOBS)
    root = pathlib.Path(tempfile.mkdtemp())
    (root / "linux-amd64").mkdir()
    (root / "linux-amd64" / "trivy.txt").write_text(TRIVY_FINDINGS)
    assert publish(fake, "release/python-base/v1.1.506", "failure", str(root)) == 0
    assert fake.verbs() == ["label", "create"]
    cmd, body = fake.calls[-1]
    assert cmd[2] == "create"
    assert "Publish failed: python-base v1.1.506 - Trivy gate: 3 fixable MEDIUM+ findings" in cmd
    assert "Total: 3" in body


def test_a_repeat_failure_updates_the_existing_issue():
    fake = FakeGitHub(TAGS, issue={"number": 7, "title": "Publish failed: python-base v1.1.505 - x"},
                      jobs=FAILED_JOBS)
    publish(fake, "release/python-base/v1.1.506", "failure")
    assert [c[0][2] for c in fake.calls] == ["edit", "comment"]
    assert "7" in fake.calls[0][0]


def test_the_next_successful_publish_closes_the_issue():
    fake = FakeGitHub(TAGS, issue={"number": 7, "title": "Publish failed: python-base v1.1.505 - x"})
    publish(fake, "release/python-base/v1.1.506", "success")
    assert [c[0][2] for c in fake.calls] == ["close"]


def test_a_cancelled_run_leaves_the_issue_alone():
    fake = FakeGitHub(TAGS, issue={"number": 7, "title": "Publish failed: python-base v1.1.505 - x"})
    publish(fake, "release/python-base/v1.1.506", "cancelled")
    assert fake.calls == []


def tracking(fake, report_text):
    report = pathlib.Path(tempfile.mkdtemp()) / "r.md"
    report.write_text(report_text)
    fake.install()
    try:
        return pr.cmd_tracking_issue(argparse.Namespace(
            repo="o/r", label=pr.STALE_LABEL, title=pr.STALE_TITLE, intro="intro",
            report=str(report), run_url="https://run/2"))
    finally:
        fake.restore()


def test_tracking_issue_opens_and_fails_while_stale_then_closes():
    fake = FakeGitHub()
    assert tracking(fake, "- `x`: behind\n") == 1
    assert [c[0][2] for c in fake.calls if c[0][0] == "gh"] == ["create"]
    fake = FakeGitHub(issue={"number": 3, "title": pr.STALE_TITLE})
    assert tracking(fake, "- `x`: still behind\n") == 1
    assert [c[0][2] for c in fake.calls] == ["comment"]
    fake = FakeGitHub(issue={"number": 3, "title": pr.STALE_TITLE})
    assert tracking(fake, "\n") == 0
    assert [c[0][2] for c in fake.calls] == ["close"]
    fake = FakeGitHub()
    assert tracking(fake, "") == 0 and fake.calls == []


def test_stale_skips_images_this_run_just_rebuilt():
    saved = pr.release_tags, pr.image_version_label, pr.latest_publish_run
    out = pathlib.Path(tempfile.mkdtemp()) / "s.md"
    pr.release_tags = lambda repo, image: [f"release/{image}/v1.0.1"]
    pr.image_version_label = lambda ref: "v1.0.0"
    pr.latest_publish_run = lambda repo, tag: None
    try:
        pr.cmd_stale(argparse.Namespace(repo="o/r", registry="ghcr.io", images="a b",
                                        skip="b", out=str(out)))
    finally:
        pr.release_tags, pr.image_version_label, pr.latest_publish_run = saved
    report = out.read_text()
    assert "`a`" in report and "`b`" not in report


if __name__ == "__main__":
    # Runnable without pytest, so CI needs no extra dependency.
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    for name, fn in tests:
        fn()
        print(f"ok   {name}")
    print(f"{len(tests)} passed")
