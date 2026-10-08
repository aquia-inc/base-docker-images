#!/usr/bin/env python3
"""Decide which images need a new release, from what actually goes into them.

An image is released when any of its build inputs changed since its newest
release tag (release/<image>/vX.Y.Z). The inputs are derived from the
Dockerfile itself rather than listed by hand, so a new COPY is covered the day
it is added:

  - Dockerfile.<image>
  - tests/container-structure/<image>.yaml
  - every local COPY / ADD source in the Dockerfile
  - SHARED_INPUTS, which affect every image (the scanner policy and the
    workflow and actions that build, test and gate the image)

Comparing against the previous release tag, not the previous commit, means a
change that was merged while tagging failed or was skipped is still picked up
by the next run.

Usage:
  release-inputs.py changed           JSON list of images to release
  release-inputs.py inputs <image>    the derived input paths, one per line

Fails (exit 1) rather than guess: a COPY source it cannot resolve, or any git
error, stops the run instead of reporting "nothing changed".
"""

from __future__ import annotations

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
)

DOCKERFILE_PREFIX = "Dockerfile."
RELEASE_VERSION = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
INSTRUCTION = re.compile(r"^\s*(COPY|ADD)\s+(.*)$", re.IGNORECASE)
REMOTE = re.compile(r"^(https?://|git@|ssh://)", re.IGNORECASE)
GLOB = re.compile(r"[*?\[]")


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


def pathspec(path: str) -> str:
    return f":(glob){path}" if GLOB.search(path) else path


def git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=False)


def images(repo: Path) -> list[str]:
    result = git(repo, "ls-files", "--", f"{DOCKERFILE_PREFIX}*")
    if result.returncode != 0:
        raise RuntimeError(f"git ls-files failed: {result.stderr.strip()}")
    names = [p[len(DOCKERFILE_PREFIX):] for p in result.stdout.split() if "/" not in p]
    return sorted(names)


def latest_release(repo: Path, image: str) -> str | None:
    result = git(repo, "tag", "--list", f"release/{image}/v*")
    if result.returncode != 0:
        raise RuntimeError(f"git tag failed: {result.stderr.strip()}")
    best, best_key = None, None
    for tag in result.stdout.split():
        match = RELEASE_VERSION.match(tag.rsplit("/", 1)[-1])
        if not match:
            continue
        key = tuple(int(n) for n in match.groups())
        if best_key is None or key > best_key:
            best, best_key = tag, key
    return best


def changed_inputs(repo: Path, image: str, head: str = "HEAD") -> tuple[str | None, list[str]]:
    """The baseline tag, and which inputs differ between it and head.

    No release tag at all means the image has never been released, which is
    reported as a change to its Dockerfile.
    """
    baseline = latest_release(repo, image)
    inputs = image_inputs(repo, image)
    if baseline is None:
        return None, [f"{DOCKERFILE_PREFIX}{image}"]
    result = git(repo, "diff", "--name-only", baseline, head, "--",
                 *(pathspec(p) for p in inputs))
    if result.returncode != 0:
        raise RuntimeError(f"git diff {baseline}..{head} failed: {result.stderr.strip()}")
    return baseline, result.stdout.split()


def changed_images(repo: Path, head: str = "HEAD", log=sys.stderr) -> list[str]:
    selected = []
    for image in images(repo):
        baseline, changed = changed_inputs(repo, image, head)
        if changed:
            selected.append(image)
            shown = ", ".join(changed[:5]) + (f" (+{len(changed) - 5} more)" if len(changed) > 5 else "")
            print(f"{image}: release, changed since {baseline or 'never released'}: {shown}",
                  file=log)
        else:
            print(f"{image}: no input changed since {baseline}", file=log)
    return selected


def main(argv: list[str]) -> int:
    repo = Path.cwd()
    try:
        if argv[:1] == ["changed"] and len(argv) == 1:
            print(json.dumps(changed_images(repo)))
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
