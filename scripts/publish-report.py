#!/usr/bin/env python3
"""Make a failed publish and a stale `:latest` impossible to miss.

Two jobs use this:

  publish  After a release-tag publish run, keep one issue per image: open or
           update it when the run failed, close it when the image's next
           publish succeeds. The title names the real reason - a Trivy
           finding count only when Trivy found findings - and the body carries
           the gate's own output.

  stale    In the daily job, compare every image's published `:latest` with
           its newest release tag. A mismatch that is not a publish still in
           flight means a release never landed, and says why.

  tracking-issue
           Open, update or close a single tracking issue from a report file.

Only the newest release of an image can open or close its issue. A re-run of
an older tag runs that tag's old tree and can never be what consumers pull,
so it is reported in the log and nothing else.

Everything that touches GitHub or the registry goes through `gh` and
`docker`; the decisions are plain functions, unit-tested in
test_publish_report.py.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

PUBLISH_WORKFLOW = "publish-base-images.yml"
FAILURE_LABEL = "publish-failure"
STALE_LABEL = "stale-latest"
STALE_TITLE = "Published :latest is behind its newest release"
RELEASE_TAG = re.compile(r"^release/(?P<image>[a-z0-9][a-z0-9.-]*)/(?P<version>v\d+\.\d+\.\d+)$")
VERSION = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
TRIVY_TOTAL = re.compile(r"^Total: (\d+)", re.MULTILINE)
TRIVY_FATAL = re.compile(r"\bFATAL\b|Fatal error")
IN_FLIGHT = {"queued", "in_progress", "waiting", "requested", "pending"}
# Keep the issue body under GitHub's 65536-character limit with room to spare.
MAX_SECTION = 12000


# ---------------------------------------------------------------------------
# Decisions (pure)
# ---------------------------------------------------------------------------

def parse_tag(tag: str) -> tuple[str, str]:
    match = RELEASE_TAG.match(tag)
    if not match:
        raise ValueError(f"not a release tag: {tag}")
    return match.group("image"), match.group("version")


def version_key(version: str) -> tuple[int, int, int] | None:
    match = VERSION.match(version)
    return tuple(int(n) for n in match.groups()) if match else None


def newest_release(tags: list[str], image: str) -> str | None:
    best, best_key = None, None
    for tag in tags:
        match = RELEASE_TAG.match(tag)
        if not match or match.group("image") != image:
            continue
        key = version_key(match.group("version"))
        if best_key is None or key > best_key:
            best, best_key = tag, key
    return best


def count_findings(trivy_output: str) -> int:
    """Sum of Trivy's per-target "Total: N" lines in table output."""
    return sum(int(n) for n in TRIVY_TOTAL.findall(trivy_output))


def scan_failed_to_run(trivy_output: str) -> bool:
    return bool(TRIVY_FATAL.search(trivy_output))


def failed_steps(jobs: list[dict]) -> list[tuple[str, str]]:
    """(job, step) for every failed step; (job, "") for a failed job with none."""
    failed = []
    for job in jobs:
        if job.get("conclusion") not in ("failure", "timed_out"):
            continue
        steps = [s["name"] for s in job.get("steps", []) if s.get("conclusion") == "failure"]
        failed += [(job["name"], s) for s in steps] or [(job["name"], "")]
    return failed


def classify(failed: list[tuple[str, str]], trivy_outputs: list[str]) -> str:
    """One-line reason for an issue title. Never a CVE count unless Trivy found CVEs."""
    if any(step.startswith("Run Trivy vulnerability scanner") for _, step in failed):
        if any(scan_failed_to_run(t) for t in trivy_outputs):
            return "Trivy could not scan the image"
        total = sum(count_findings(t) for t in trivy_outputs)
        if total:
            return f"Trivy gate: {total} fixable MEDIUM+ finding{'s' if total != 1 else ''}"
        return "Trivy gate failed"
    if any(step.startswith("Run Container Structure Tests") for _, step in failed):
        return "container structure tests failed"
    if failed:
        job, step = failed[0]
        return f"{step} failed" if step else f"{job} failed"
    return "publish did not complete"


def failure_title(image: str, version: str, reason: str) -> str:
    return f"Publish failed: {image} {version} - {reason}"


def is_issue_for(title: str, image: str) -> bool:
    # The trailing space keeps go-base from matching go-base-1.27.
    return title.startswith(f"Publish failed: {image} ")


def section(heading: str, text: str) -> str:
    text = text.strip()
    if not text:
        return ""
    if len(text) > MAX_SECTION:
        text = text[:MAX_SECTION] + "\n... (truncated; the full output is in the run log)"
    return f"<details><summary>{heading}</summary>\n\n```\n{text}\n```\n\n</details>\n"


def failure_body(tag: str, run_url: str, failed: list[tuple[str, str]],
                 gate: dict[str, dict[str, str]]) -> str:
    lines = [f"Publishing `{tag}` failed: {run_url}", "", "Failed:"]
    lines += [f"- {job}: {step or '(job failed before any step reported)'}" for job, step in failed]
    if not failed:
        lines.append("- no failed step was reported; the run did not complete")
    lines.append("")
    for platform in sorted(gate):
        lines.append(section(f"Trivy gate output, {platform}", gate[platform].get("trivy", "")))
        lines.append(section(f"Container structure test output, {platform}",
                             gate[platform].get("structure-tests", "")))
    lines.append("This issue closes automatically when this image's next release publishes.")
    return "\n".join(line for line in lines if line is not None)


def stale_reason(image: str, newest_tag: str | None, latest_versions: dict[str, str | None],
                 run: dict | None) -> str | None:
    """Why `:latest` is behind the newest release, or None if it is not (or not yet)."""
    if newest_tag is None:
        return None
    _, newest = parse_tag(newest_tag)
    if all(v == newest for v in latest_versions.values()):
        return None
    shown = ", ".join(f"{arch} {v or 'unreadable'}" for arch, v in sorted(latest_versions.items()))
    if run is None:
        return f"`{image}`: `{newest_tag}` never started a publish; `:latest` is {shown}"
    if run.get("status") in IN_FLIGHT:
        return None
    url = run.get("html_url", "")
    if run.get("conclusion") == "success":
        return (f"`{image}`: `{newest_tag}` published successfully but `:latest` is still "
                f"{shown} ({url})")
    return f"`{image}`: publishing `{newest_tag}` ended `{run.get('conclusion')}`; `:latest` is {shown} ({url})"


# ---------------------------------------------------------------------------
# GitHub and registry (thin wrappers over gh and docker)
# ---------------------------------------------------------------------------

def run(*cmd: str, stdin: str | None = None) -> str:
    result = subprocess.run(cmd, input=stdin, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])} failed: {result.stderr.strip()[:500]}")
    return result.stdout


def gh_json(*args: str):
    return json.loads(run("gh", *args) or "null")


def release_tags(repo: str, image: str) -> list[str]:
    refs = gh_json("api", "--paginate", f"repos/{repo}/git/matching-refs/tags/release/{image}/v")
    return [r["ref"].removeprefix("refs/tags/") for r in refs or []]


def run_jobs(repo: str, run_id: str) -> list[dict]:
    data = gh_json("api", "--paginate", f"repos/{repo}/actions/runs/{run_id}/jobs?filter=latest")
    return data.get("jobs", []) if isinstance(data, dict) else []


def latest_publish_run(repo: str, tag: str) -> dict | None:
    data = gh_json("api", f"repos/{repo}/actions/workflows/{PUBLISH_WORKFLOW}/runs"
                          f"?branch={tag}&event=push&per_page=1")
    runs = data.get("workflow_runs", []) if isinstance(data, dict) else []
    return runs[0] if runs else None


def image_version_label(reference: str) -> str | None:
    try:
        out = run("docker", "buildx", "imagetools", "inspect", reference,
                  "--format", "{{json .Image}}")
    except RuntimeError:
        return None
    return version_label(json.loads(out or "null") or {})


def version_label(image: dict) -> str | None:
    """The version label of a single image, or of an index's first platform.

    imagetools reports a single image as its config, and an index as a map of
    platform to config; both describe the same release.
    """
    if "config" not in image:
        platforms = [v for k, v in sorted(image.items())
                     if isinstance(v, dict) and "config" in v and k != "unknown/unknown"]
        image = platforms[0] if platforms else {}
    labels = (image.get("config") or {}).get("Labels") or {}
    return labels.get("org.opencontainers.image.version")


def open_issue(repo: str, label: str, match) -> dict | None:
    issues = gh_json("issue", "list", "--repo", repo, "--label", label, "--state", "open",
                     "--limit", "100", "--json", "number,title")
    return next((i for i in issues or [] if match(i["title"])), None)


def ensure_label(repo: str, label: str, description: str) -> None:
    subprocess.run(["gh", "label", "create", label, "--repo", repo, "--color", "B60205",
                    "--description", description], capture_output=True, check=False)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def read_gate(gate_dir: Path) -> dict[str, dict[str, str]]:
    """gate_dir/<platform>/{trivy,structure-tests}.txt, as uploaded by publish_image."""
    gate: dict[str, dict[str, str]] = {}
    if not gate_dir.is_dir():
        return gate
    for platform_dir in sorted(p for p in gate_dir.iterdir() if p.is_dir()):
        gate[platform_dir.name] = {
            f.stem: f.read_text(errors="replace") for f in platform_dir.glob("*.txt")}
    return gate


def cmd_publish(args) -> int:
    image, version = parse_tag(args.tag)
    newest = newest_release(release_tags(args.repo, image), image)
    if newest != args.tag:
        print(f"{args.tag} is not the newest release of {image} ({newest}); a re-run of an "
              f"older tag cannot describe what consumers pull, so no issue is changed.")
        return 0
    if args.outcome == "cancelled":
        print("Run was cancelled; leaving the issue state as it is.")
        return 0

    existing = open_issue(args.repo, FAILURE_LABEL, lambda t: is_issue_for(t, image))
    if args.outcome == "success":
        if existing:
            run("gh", "issue", "close", str(existing["number"]), "--repo", args.repo,
                "--comment", f"`{args.tag}` published successfully: {args.run_url}")
            print(f"closed #{existing['number']}")
        else:
            print(f"{image}: published, no open failure issue")
        return 0

    failed = failed_steps(run_jobs(args.repo, args.run_id))
    gate = read_gate(Path(args.gate_dir))
    reason = classify(failed, [g.get("trivy", "") for g in gate.values()])
    title = failure_title(image, version, reason)
    body = failure_body(args.tag, args.run_url, failed, gate)
    print(f"::error::{title} ({args.run_url})")
    if existing:
        number = str(existing["number"])
        run("gh", "issue", "edit", number, "--repo", args.repo, "--title", title)
        run("gh", "issue", "comment", number, "--repo", args.repo, "--body-file", "-", stdin=body)
        print(f"updated #{number}")
    else:
        ensure_label(args.repo, FAILURE_LABEL, "A release tag failed to publish")
        run("gh", "issue", "create", "--repo", args.repo, "--title", title,
            "--label", FAILURE_LABEL, "--body-file", "-", stdin=body)
    return 0


def cmd_stale(args) -> int:
    reasons = []
    skip = set(args.skip.split())
    for image in args.images.split():
        if image in skip:
            # Its rebuild tag was pushed moments ago by this same run, so its
            # publish may not even be registered yet.
            print(f"{image}: rebuild dispatched by this run, checked tomorrow")
            continue
        newest = newest_release(release_tags(args.repo, image), image)
        if newest is None:
            print(f"{image}: no release tag, skipped")
            continue
        base = f"{args.registry}/{args.repo}/{image}"
        latest = {arch: image_version_label(f"{base}-linux-{arch}:latest") for arch in ("amd64", "arm64")}
        # The multi-arch tag is written by a later job than the per-architecture
        # ones, so it can fall behind on its own.
        latest["multi-arch"] = image_version_label(f"{base}:latest")
        reason = stale_reason(image, newest, latest, latest_publish_run(args.repo, newest))
        if reason is None:
            print(f"{image}: :latest matches {newest} or its publish is still running")
        else:
            print(f"::error::{reason}")
            reasons.append(reason)
    Path(args.out).write_text("".join(f"- {r}\n" for r in reasons))
    return 0


def cmd_tracking_issue(args) -> int:
    report = Path(args.report).read_text().strip()
    existing = open_issue(args.repo, args.label, lambda t: t == args.title)
    if not report:
        if existing:
            run("gh", "issue", "close", str(existing["number"]), "--repo", args.repo,
                "--comment", f"Resolved: {args.run_url}")
            print(f"closed #{existing['number']}")
        return 0
    body = f"{args.intro}\n\n{report}\n\nRun: {args.run_url}\n"
    if existing:
        run("gh", "issue", "comment", str(existing["number"]), "--repo", args.repo,
            "--body-file", "-", stdin=body)
    else:
        ensure_label(args.repo, args.label, args.title)
        run("gh", "issue", "create", "--repo", args.repo, "--title", args.title,
            "--label", args.label, "--body-file", "-", stdin=body)
    # Still a failure: the issue is the durable record, not a substitute for red.
    print(f"::error::{args.title}. See the tracking issue.")
    return 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("publish")
    p.add_argument("--repo", required=True)
    p.add_argument("--tag", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--run-url", required=True)
    p.add_argument("--outcome", required=True, choices=["success", "failure", "cancelled"])
    p.add_argument("--gate-dir", default="gate-reports")
    p.set_defaults(fn=cmd_publish)
    s = sub.add_parser("stale")
    s.add_argument("--repo", required=True)
    s.add_argument("--registry", default="ghcr.io")
    s.add_argument("--images", required=True)
    s.add_argument("--skip", default="", help="images whose rebuild this run just dispatched")
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_stale)
    t = sub.add_parser("tracking-issue")
    t.add_argument("--repo", required=True)
    t.add_argument("--label", required=True)
    t.add_argument("--title", required=True)
    t.add_argument("--intro", required=True)
    t.add_argument("--report", required=True)
    t.add_argument("--run-url", required=True)
    t.set_defaults(fn=cmd_tracking_issue)
    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except (RuntimeError, ValueError, OSError, json.JSONDecodeError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
