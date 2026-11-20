#!/usr/bin/env python3
"""Decide which images need a new release, from what actually goes into them.

An image is released when any of its build inputs changed since its newest
release tag (release/<image>/vX.Y.Z) whose publish did not fail. The inputs are
derived from the Dockerfile itself rather than listed by hand, so a new COPY is
covered the day it is added:

  - Dockerfile.<image>
  - tests/container-structure/<image>.yaml
  - every local COPY / ADD source in the Dockerfile
  - SHARED_INPUTS, which affect every image (the scanner policy, and the
    workflow, actions, guard scripts and signing script that build, test,
    gate and sign it)

Comparing against the previous release tag, not the previous commit, means a
change that was merged while tagging failed or was skipped is still picked up
by the next run.

A tag whose publish run ended in anything but success is passed over, so a
change it carried is released again by the next run instead of waiting for
the image's next input change. Only a finished run counts as failed: a tag
whose publish is queued or still running is the baseline, otherwise two
merges a minute apart would release the same change twice. A run that was
re-run to success counts as success. The lookup reads the PUBLISH_RUN_PAGES
most recent tag-push runs of the publish workflow; a tag older than that
window is the baseline whatever its outcome.

Usage:
  release-inputs.py changed [--repo OWNER/NAME]
                                      JSON list of images to release; with
                                      --repo, tags whose publish failed in
                                      that repository are passed over
  release-inputs.py since <commit>    JSON list of images whose inputs differ
                                      between <commit> (a full commit id) and
                                      HEAD, release tags aside: what a pull
                                      request must build before it merges
  release-inputs.py red --repo OWNER/NAME
                                      JSON list of images whose newest release
                                      tag's publish failed in that repository
  release-inputs.py inputs <image>    the derived input paths, one per line

Fails (exit 1) rather than guess: a COPY source it cannot resolve, or any git
or GitHub API error, stops the run instead of reporting "nothing changed".
"""

from __future__ import annotations

import itertools
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

SHARED_INPUTS = (
    "trivy.yaml",
    ".trivyignore.yaml",
    ".dockerignore",
    ".github/workflows/publish-base-images.yml",
    ".github/actions",
    "scripts/sign-and-tag.sh",
    "scripts/check-*.sh",
)

DOCKERFILE_PREFIX = "Dockerfile."
PUBLISH_WORKFLOW = "publish-base-images.yml"
PUBLISH_RUN_PAGES = 3  # of 100 runs each; a full eight-image wave is 8 runs
RELEASE_VERSION = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
INSTRUCTION = re.compile(r"^\s*(COPY|ADD)\s+(.*)$", re.IGNORECASE)
REMOTE = re.compile(r"^(https?://|git@|ssh://)", re.IGNORECASE)
GLOB = re.compile(r"[*?\[]")
# A full commit id (SHA-1 or SHA-256 object format), never a ref name or an
# option: the value comes from the workflow and is handed to git.
COMMIT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
# An image name: it comes from a file name and ends up in job names, tags,
# GITHUB_ENV and log lines, so nothing but a plain name is accepted.
PLAIN_IMAGE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")


class InputError(Exception):
    """A Dockerfile input that cannot be resolved to a repository path."""


def logical_lines(text: str) -> list[str]:
    """Dockerfile lines with comments dropped and continuations joined."""
    lines, current = [], ""
    for raw in text.splitlines():
        stripped = raw.strip()
        # Docker drops comment lines, and tolerates blank ones, even inside a
        # continuation, so neither may end the instruction being joined.
        if stripped.startswith("#") or (current and not stripped):
            continue
        if stripped.endswith("\\"):
            current += stripped[:-1] + " "
            continue
        current += stripped
        if current:
            lines.append(current)
        current = ""
    if current:
        lines.append(current)
    return lines


def copy_sources(text: str) -> list[str]:
    """Local source paths of every COPY / ADD that reads the build context."""
    sources: list[str] = []
    for line in logical_lines(text):
        match = INSTRUCTION.match(line)
        if not match:
            continue
        args = match.group(2).strip()
        if args.startswith("<<") or " <<" in args:
            continue  # heredoc: the content is inline, not a file
        if args.startswith("["):
            try:
                tokens = json.loads(args)
            except json.JSONDecodeError as error:
                raise InputError(f"unparseable {match.group(1)}: {line}") from error
        else:
            tokens = shlex.split(args)
        if any(t.startswith("--from=") for t in tokens):
            continue  # copies from another stage or image, not the context
        operands = [t for t in tokens if not t.startswith("--")]
        if len(operands) < 2:
            raise InputError(f"{match.group(1)} without a source and destination: {line}")
        for source in operands[:-1]:
            if REMOTE.match(source):
                continue
            if "$" in source:
                raise InputError(f"cannot resolve a variable in a {match.group(1)} source: {source}")
            source = source.removeprefix("./").rstrip("/") or "."
            sources.append(source)
    return sources


def image_inputs(repo: Path, image: str) -> list[str]:
    dockerfile = f"{DOCKERFILE_PREFIX}{image}"
    text = (repo / dockerfile).read_text()
    inputs = [dockerfile, f"tests/container-structure/{image}.yaml"]
    inputs += copy_sources(text)
    inputs += SHARED_INPUTS
    return list(dict.fromkeys(inputs))


def pathspecs(path: str) -> list[str]:
    # Always with explicit magic, so a COPY source such as ":!x" or
    # ":(exclude)x" is a path to git and can never exclude another input. Not
    # "top": it stops git normalising "./", "a//b" and "a/../b", which docker
    # reads as paths in the context, and those inputs would select nothing.
    if GLOB.search(path):
        # COPY of a glob copies each directory it matches whole.
        return [f":(glob){path}", f":(glob){path}/**"]
    return [f":(literal){path}"]


def git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=False)


def images(repo: Path) -> list[str]:
    result = git(repo, "ls-files", "-z", "--", f"{DOCKERFILE_PREFIX}*")
    if result.returncode != 0:
        raise RuntimeError(f"git ls-files failed: {result.stderr.strip()}")
    names = []
    for path in result.stdout.split("\0"):
        if not path.startswith(DOCKERFILE_PREFIX) or "/" in path:
            continue
        name = path[len(DOCKERFILE_PREFIX):]
        if not PLAIN_IMAGE.fullmatch(name) or ".." in name:
            raise InputError(f"{path!r}: not a plain image name (lowercase letters, digits, "
                             "'.', '_' and '-', starting with a letter or digit)")
        names.append(name)
    return sorted(names)


def release_tags(repo: Path, image: str) -> list[str]:
    """The image's release tags, newest version first."""
    result = git(repo, "tag", "--list", f"release/{image}/v*")
    if result.returncode != 0:
        raise RuntimeError(f"git tag failed: {result.stderr.strip()}")
    keyed = []
    for tag in result.stdout.split():
        match = RELEASE_VERSION.match(tag.rsplit("/", 1)[-1])
        if match:
            keyed.append((tuple(int(n) for n in match.groups()), tag))
    return [tag for _, tag in sorted(keyed, reverse=True)]


def latest_release(repo: Path, image: str,
                   failed: frozenset[str] | set[str] = frozenset()) -> str | None:
    """The newest release tag, passing over any whose publish failed."""
    return next((tag for tag in release_tags(repo, image) if tag not in failed), None)


def red_images(repo: Path, failed: frozenset[str] | set[str]) -> list[str]:
    """Images whose newest release tag's publish failed: main already cannot
    publish them, so a pull request leg of one does not gate the merge."""
    red = []
    for image in images(repo):
        tags = release_tags(repo, image)
        if tags and tags[0] in failed:
            red.append(image)
    return red


def failed_publishes(runs: list[dict]) -> set[str]:
    """Release tags whose newest publish run finished in anything but success.

    A queued or running publish is not a failure. A re-run is the same run
    with a later attempt, so it carries the final conclusion; a tag pushed
    again is judged on its newest run only.
    """
    seen, failed = set(), set()
    for run in sorted(runs, key=lambda r: r.get("created_at") or "", reverse=True):
        tag = run.get("head_branch") or ""
        if not tag.startswith("release/") or tag in seen:
            continue
        seen.add(tag)
        if run.get("status") == "completed" and run.get("conclusion") != "success":
            failed.add(tag)
    return failed


def publish_runs(repository: str, pages: int = PUBLISH_RUN_PAGES) -> list[dict]:
    """The most recent tag-push runs of the publish workflow, read with gh."""
    if not REPOSITORY.match(repository):
        raise InputError(f"not an OWNER/NAME repository: {repository}")
    runs: list[dict] = []
    for page in range(1, pages + 1):
        result = subprocess.run(
            ["gh", "api", f"repos/{repository}/actions/workflows/{PUBLISH_WORKFLOW}/runs"
                          f"?event=push&per_page=100&page={page}"],
            capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"listing {PUBLISH_WORKFLOW} runs failed: {result.stderr.strip()}")
        try:
            batch = json.loads(result.stdout).get("workflow_runs", [])
        except (ValueError, AttributeError) as error:
            raise RuntimeError(f"unreadable {PUBLISH_WORKFLOW} runs response: {error}") from error
        runs += batch
        if len(batch) < 100:
            break
    return runs


def changed_inputs(repo: Path, image: str, head: str = "HEAD",
                   failed: frozenset[str] | set[str] = frozenset()) -> tuple[str | None, list[str]]:
    """The baseline tag, and which inputs differ between it and head.

    No release tag at all means the image has never been released, which is
    reported as a change to its Dockerfile. So does an image whose every
    release failed to publish.
    """
    baseline = latest_release(repo, image, failed)
    if baseline is None:
        image_inputs(repo, image)  # still fail on a COPY source it cannot resolve
        return None, [f"{DOCKERFILE_PREFIX}{image}"]
    return baseline, diff_inputs(repo, image, baseline, head)


def diff_inputs(repo: Path, image: str, base: str, head: str) -> list[str]:
    """Which of the image's inputs differ between two commits."""
    result = git(repo, "diff", "--name-only", base, head, "--",
                 *(spec for p in image_inputs(repo, image) for spec in pathspecs(p)))
    if result.returncode != 0:
        raise RuntimeError(f"git diff {base}..{head} failed: {result.stderr.strip()}")
    return result.stdout.split()


def changed_since(repo: Path, base: str, head: str = "HEAD", log=sys.stderr) -> list[str]:
    """Images whose inputs differ between base and head, whatever was released.

    This is the pull request question: which images does this change touch?
    GitHub checks out the merge of the pull request into its base, and base is
    the base branch commit that merge was made on, so the diff is exactly what
    merging would change - the same inputs `changed` releases after the merge.
    """
    if not COMMIT_ID.fullmatch(base):
        raise InputError(f"not a full lowercase commit id: {base!r}")
    selected = []
    for image in images(repo):
        changed = diff_inputs(repo, image, base, head)
        if changed:
            selected.append(image)
            shown = ", ".join(changed[:5]) + (f" (+{len(changed) - 5} more)" if len(changed) > 5 else "")
            print(f"{image}: build, changed since {base[:12]}: {shown}", file=log)
        else:
            print(f"{image}: no input changed since {base[:12]}", file=log)
    return selected


def changed_images(repo: Path, head: str = "HEAD", log=sys.stderr,
                   failed: frozenset[str] | set[str] = frozenset()) -> list[str]:
    selected = []
    for image in images(repo):
        baseline, changed = changed_inputs(repo, image, head, failed)
        # Every tag newer than the baseline was passed over for a failed publish.
        passed = list(itertools.takewhile(lambda t: t != baseline, release_tags(repo, image)))
        note = f" (passed over {', '.join(passed)}: publish failed)" if passed else ""
        if changed:
            selected.append(image)
            shown = ", ".join(changed[:5]) + (f" (+{len(changed) - 5} more)" if len(changed) > 5 else "")
            print(f"{image}: release, changed since {baseline or 'never released'}{note}: {shown}",
                  file=log)
        else:
            print(f"{image}: no input changed since {baseline}{note}", file=log)
    return selected


def main(argv: list[str]) -> int:
    repo = Path.cwd()
    try:
        if argv[:1] == ["changed"] and (len(argv) == 1 or (len(argv) == 3 and argv[1] == "--repo")):
            failed: set[str] = set()
            if len(argv) == 3:
                runs = publish_runs(argv[2])
                failed = failed_publishes(runs)
                print(f"read {len(runs)} recent publish runs; failed: "
                      f"{', '.join(sorted(failed)) or 'none'}", file=sys.stderr)
            print(json.dumps(changed_images(repo, failed=failed)))
            return 0
        if argv[:1] == ["since"] and len(argv) == 2:
            print(json.dumps(changed_since(repo, argv[1])))
            return 0
        if argv[:1] == ["red"] and len(argv) == 3 and argv[1] == "--repo":
            runs = publish_runs(argv[2])
            red = red_images(repo, failed_publishes(runs))
            print(f"read {len(runs)} recent publish runs; newest release failed: "
                  f"{', '.join(red) or 'none'}", file=sys.stderr)
            print(json.dumps(red))
            return 0
        if argv[:1] == ["inputs"] and len(argv) == 2:
            print("\n".join(image_inputs(repo, argv[1])))
            return 0
    except (InputError, RuntimeError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
