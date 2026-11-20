#!/usr/bin/env python3
"""Invariants of the image Dockerfiles that no build failure would report.

Every image floats its apk packages to the newest build the repository offers,
and the publish gate (scripts/check-package-freshness.sh) fails an image that
ships anything older. "apk upgrade" alone does not guarantee that: when Wolfi
split libpng into libpng + libpng16-16 (2026-11-02), the solver kept the old
libpng as the provider of so:libpng16.so.16 and openjdk17-base failed the gate
on every build. So the final stage of every image that runs apk ends its
install step by upgrading, by name, each package "apk version -l '<'" still
lists - the same list the gate reports - with pipefail, so a failing
"apk version" fails the build instead of upgrading nothing.

Run: python3 scripts/test_dockerfile_invariants.py
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
STALE_LIST = "apk version -l '<'"
# The step, word for word once whitespace is collapsed. A text this exact is
# what lets the check tell the step from an edit that keeps its words but
# stops it working (a dry run, a sed that empties the names, a head -n 0).
STEP = re.compile(
    r"apk update && (?P<inline>set -o pipefail && )?"
    r"apk version -l '<' \| tail -n \+2 \| awk '\{print \$1\}'"
    r" \| sed -E 's/-\[0-9\]\[\^-\]\*-r\[0-9\]\+\$//'"
    r" \| xargs -r apk add --no-cache --upgrade"
)
# An apk command that installs or upgrades, with any global flags (and their
# values, as in -X <url> or --wait 30) before the subcommand, within one
# command. Run on text whose quotes, commas and brackets are blanked, so
# exec-form RUNs (["apk", "add", ...]) are read the same way.
APK_INSTALL = re.compile(r"\bapk\b[^;&|]*?\s(?:add|upgrade|fix)\b")
HEREDOC = re.compile(r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?")
# Images whose final stage runs apk. nginx-base ships cgr.dev/chainguard/nginx,
# which has no package manager; its builder stage is discarded.
EXPECTED_IMAGES = {
    "fips-140-3",
    "go-base",
    "go-base-1.27",
    "nodejs-base",
    "openjdk17-base",
    "python-base",
    "wolfi-base",
}


def instructions(path: Path) -> list[tuple[str, str]]:
    """(keyword, arguments) per instruction, continuations joined and comment
    lines dropped, as the Docker parser does. A heredoc body is appended to
    its RUN, so apk inside one is still seen (and refused: see problems)."""
    result: list[tuple[str, str]] = []
    pending = ""
    lines = iter(path.read_text(encoding="utf-8").splitlines())
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        pending += line
        keyword, args = (re.split(r"\s+", pending, maxsplit=1) + [""])[:2]
        heredoc = HEREDOC.search(args) if keyword.upper() == "RUN" else None
        if heredoc:
            body = []
            for raw_body in lines:
                if raw_body.strip() == heredoc.group(1):
                    break
                body.append(raw_body.strip())
            args += " " + " ; ".join(body)
        result.append((keyword.upper(), args.strip()))
        pending = ""
    if pending:
        keyword, args = (re.split(r"\s+", pending, maxsplit=1) + [""])[:2]
        result.append((keyword.upper(), args.strip()))
    return result


def final_stage(path: Path) -> list[tuple[str, str]]:
    """The instructions that make the final image: its stage, preceded by the
    stage it is built FROM when that is an earlier stage of this file."""
    stages: list[list[tuple[str, str]]] = []
    aliases: dict[str, int] = {}
    for keyword, args in instructions(path):
        if keyword == "FROM":
            words = [w for w in args.split() if not w.startswith("--")]
            parent = words[0].lower() if words else ""
            stages.append(list(stages[aliases[parent]]) if parent in aliases else [])
            if len(words) >= 3 and words[1].lower() == "as":
                aliases[words[2].lower()] = len(stages) - 1
        if stages:
            stages[-1].append((keyword, args))
    return stages[-1] if stages else []


def apk_installs(text: str) -> list[int]:
    blanked = re.sub(r"[\"',\[\]]", " ", text)
    return [m.start() for m in APK_INSTALL.finditer(blanked)]


def unquoted(text: str) -> list[bool]:
    """Per character: True when it is outside any shell quotes."""
    state, flags, i = "", [], 0
    while i < len(text):
        c = text[i]
        flags.append(state == "")
        if c == "\\" and state != "'":
            # The escaped character neither quotes nor ends a quote.
            flags.append(False)
            i += 2
            continue
        if state == "" and c in "'\"":
            state = c
        elif state == c:
            state = ""
        i += 1
    return flags[:len(text)]


def problems(path: Path) -> list[str]:
    stage = final_stage(path)
    apk_runs = [i for i, (k, a) in enumerate(stage) if k == "RUN" and apk_installs(a)]
    if not apk_runs:
        return []
    index = apk_runs[-1]
    raw_run = stage[index][1]
    if HEREDOC.search(raw_run):
        return ["the last apk RUN is a heredoc, which this check cannot read: write it as a plain RUN"]
    run = " ".join(raw_run.split())
    step = STEP.search(run)
    if step is None:
        return [f"last apk RUN does not upgrade by name what {STALE_LIST} lists, in the exact form of the step"]
    found: list[str] = []
    plain = unquoted(run)
    before, after = run[:step.start()].rstrip(), run[step.end():].strip()
    if not plain[step.start()]:
        found.append("the step is inside quotes, so another shell runs it, or nothing does")
    if not (before.endswith("&&") or re.fullmatch(r"(--\S+\s*)*", before)):
        found.append("the step is not chained with && to what runs before it")
    if any(c == "#" and plain[i] and (i == 0 or run[i - 1].isspace()) for i, c in enumerate(run[:step.end()])):
        found.append("a shell comment hides part of the RUN")
    if "set +o pipefail" in run:
        found.append("pipefail is switched off in the RUN")
    if after and not after.startswith("&&"):
        found.append("the step is not followed by && or the end of the RUN, so it can be skipped or its failure ignored")
    rest = run[step.end():]
    if any(plain[step.end() + i] and rest.startswith(op, i) for i in range(len(rest)) for op in ("||", ";")):
        found.append("a || or ; after the step lets the RUN succeed when the step fails")
    if any(pos >= step.end() for pos in apk_installs(run)):
        found.append("an apk command after the step can install a package the step never checked")
    if not any(pos < step.start() for pos in apk_installs(run)):
        found.append("the upgrade-by-name step does not follow an apk add or apk upgrade")
    shells = [a for k, a in stage[:index] if k == "SHELL"]
    if not step.group("inline") and not (shells and "pipefail" in shells[-1]):
        found.append("the stale-list pipeline runs without pipefail")
    return found


def tracked_dockerfiles() -> list[Path]:
    """Root Dockerfile.* files under version control: the images. Untracked
    local files are not images and are never published."""
    listed = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "--", "Dockerfile.*"],
        capture_output=True, text=True, check=True,
    ).stdout.split()
    return sorted(REPO / name for name in listed if "/" not in name)


def images_with_apk() -> dict[str, Path]:
    found = {}
    for path in tracked_dockerfiles():
        if any(k == "RUN" and apk_installs(a) for k, a in final_stage(path)):
            found[path.name.removeprefix("Dockerfile.")] = path
    return found


def test_every_image_that_runs_apk_is_checked() -> None:
    found = set(images_with_apk())
    assert found == EXPECTED_IMAGES, f"images whose final stage runs apk changed: {sorted(found ^ EXPECTED_IMAGES)}"


def test_every_image_upgrades_by_name_what_the_freshness_gate_would_flag() -> None:
    failures = []
    for name, path in images_with_apk().items():
        failures += [f"{path.name}: {p}" for p in problems(path)]
    assert not failures, "\n  " + "\n  ".join(failures)


def test_the_check_refuses_a_plain_upgrade(tmp: Path) -> None:
    sample = tmp / "Dockerfile.sample"
    sample.write_text(
        "FROM scratch\nRUN apk update && apk upgrade --no-cache && \\\n    apk add --no-cache curl\n",
        encoding="utf-8",
    )
    assert problems(sample), "a stage without the upgrade-by-name step passed"


def test_the_check_refuses_the_step_without_pipefail(tmp: Path) -> None:
    sample = tmp / "Dockerfile.sample"
    sample.write_text(
        "FROM scratch\nRUN apk add --no-cache curl && \\\n    apk update && \\\n"
        "    apk version -l '<' | tail -n +2 | awk '{print $1}' \\\n"
        "        | sed -E 's/-[0-9][^-]*-r[0-9]+$//' \\\n"
        "        | xargs -r apk add --no-cache --upgrade\n",
        encoding="utf-8",
    )
    assert any("pipefail" in p for p in problems(sample)), "a pipeline without pipefail passed"


def test_the_check_ignores_the_step_in_a_discarded_stage(tmp: Path) -> None:
    sample = tmp / "Dockerfile.sample"
    sample.write_text(
        "FROM scratch AS builder\nSHELL [\"/bin/ash\", \"-o\", \"pipefail\", \"-c\"]\n"
        "RUN apk add --no-cache curl && apk update && \\\n"
        "    apk version -l '<' | tail -n +2 | xargs -r apk add --no-cache --upgrade\n"
        "FROM scratch\nRUN apk add --no-cache curl\n",
        encoding="utf-8",
    )
    assert problems(sample), "the step in a discarded stage vouched for the final one"


GOOD_STAGE = (
    "FROM scratch\n"
    "RUN apk update && apk upgrade --no-cache && \\\n"
    "    apk add --no-cache curl && \\\n"
    "    apk update && \\\n"
    "    set -o pipefail && apk version -l '<' | tail -n +2 | awk '{print $1}' \\\n"
    "        | sed -E 's/-[0-9][^-]*-r[0-9]+$//' \\\n"
    "        | xargs -r apk add --no-cache --upgrade\n"
)
GOOD_TAIL = "xargs -r apk add --no-cache --upgrade\n"
GOOD_PIPEFAIL = "set -o pipefail && apk version"


def defeated(old: str, new: str, extra: str = "") -> str:
    assert GOOD_STAGE.count(old) == 1, old
    return GOOD_STAGE.replace(old, new) + extra


def test_the_check_refuses_each_way_of_defeating_the_step(tmp: Path) -> None:
    # Each edit defeats or bypasses the step: most keep its text but stop it
    # from upgrading anything, or from failing the build when the stale list
    # cannot be read; the rest install packages where the step never looks.
    cases = {
        "a failure ignored with || true": defeated(GOOD_TAIL, GOOD_TAIL[:-1] + " || true\n"),
        "a failure ignored with ; true": defeated(GOOD_TAIL, GOOD_TAIL[:-1] + "; true\n"),
        "a dry run": defeated(GOOD_TAIL, GOOD_TAIL[:-1] + " --simulate\n"),
        "a shell comment in front of the step": defeated("curl && \\\n", "curl && true # && \\\n"),
        "apk update only echoed": defeated("    apk update && \\\n    set", "    echo apk update && \\\n    set"),
        "pipefail switched off again": defeated(GOOD_PIPEFAIL, "set -o pipefail && set +o pipefail && apk version"),
        "pipefail set in a subshell": defeated(GOOD_PIPEFAIL, "(set -o pipefail) && apk version"),
        "the step run by an inner sh -c": defeated(
            "    set -o pipefail && apk version -l '<' | tail -n +2 | awk '{print $1}' \\\n"
            "        | sed -E 's/-[0-9][^-]*-r[0-9]+$//' \\\n"
            "        | xargs -r apk add --no-cache --upgrade\n",
            "    sh -c \"set -o pipefail && apk version -l '<' | tail -n +2 | awk '{print \\$1}' "
            "| sed -E 's/-[0-9][^-]*-r[0-9]+\\$//' | xargs -r apk add --no-cache --upgrade\"\n"),
        "the step only echoed": defeated(
            "    set -o pipefail && apk version", "    echo \"set -o pipefail && apk version",
        ).replace("--upgrade\n", "--upgrade\"\n"),
        "the names emptied by sed": defeated("sed -E 's/-[0-9][^-]*-r[0-9]+$//'", "sed -E 's/.*//'"),
        "the list cut by head": defeated("| tail -n +2 |", "| tail -n +2 | head -n 0 |"),
        "an apk add after the step": defeated(GOOD_TAIL, GOOD_TAIL[:-1] + " && \\\n    apk add --no-cache git\n"),
        "a later RUN with flags first": GOOD_STAGE + "RUN apk --no-cache add -u git\n",
        "a later RUN after a tab": GOOD_STAGE + "RUN\tapk add --no-cache git\n",
        "a later exec-form RUN": GOOD_STAGE + "RUN [\"apk\", \"add\", \"--no-cache\", \"git\"]\n",
        "a later heredoc RUN": GOOD_STAGE + "RUN <<EOF\napk add --no-cache git\nEOF\n",
        "pipefail from a SHELL that a later SHELL resets": (
            "FROM scratch\nSHELL [\"/bin/ash\", \"-o\", \"pipefail\", \"-c\"]\n"
            "SHELL [\"/bin/sh\", \"-c\"]\n"
            + GOOD_STAGE.split("\n", 1)[1].replace(GOOD_PIPEFAIL, "apk version")),
        "apk in the parent stage the final one is built from": (
            "FROM scratch AS pkgs\nRUN apk add --no-cache curl\nFROM pkgs\nUSER nonroot\n"),
        "a flag-first apk add and no step": "FROM scratch\nRUN apk --no-cache add curl\n",
        "a later RUN with a flag that takes a value": (
            GOOD_STAGE + "RUN apk -X https://packages.example.invalid/os add git\n"),
        "an apk add after the step with a flag that takes a value": defeated(
            GOOD_TAIL, GOOD_TAIL[:-1] + " && \\\n    apk --repository https://packages.example.invalid/os add git\n"),
        "a --wait apk add and no step": "FROM scratch\nRUN apk --wait 30 add curl\n",
    }
    survived = []
    for name, text in cases.items():
        sample = tmp / "Dockerfile.sample"
        sample.write_text(text, encoding="utf-8")
        if not problems(sample):
            survived.append(name)
    assert not survived, "passed the check: " + "; ".join(survived)


def test_the_check_accepts_the_step_in_its_supported_forms(tmp: Path) -> None:
    cases = {
        "inline pipefail": GOOD_STAGE,
        "pipefail from SHELL": (
            "FROM scratch\nSHELL [\"/bin/ash\", \"-o\", \"pipefail\", \"-c\"]\n"
            + GOOD_STAGE.split("\n", 1)[1].replace(GOOD_PIPEFAIL, "apk version")),
        "more commands after the step": defeated(
            GOOD_TAIL, GOOD_TAIL[:-1] + " && \\\n    mkdir -p /home/nonroot/.m2\n"),
        "a package list over several lines with a comment": defeated(
            "    apk add --no-cache curl && \\\n",
            "    apk add --no-cache \\\n        # the client\n        curl \\\n        git && \\\n"),
        "a RUN flag": GOOD_STAGE.replace("RUN apk update", "RUN --mount=type=cache,target=/var/cache/apk apk update"),
        "a later RUN that only removes packages": GOOD_STAGE + "RUN apk del --no-cache curl\n",
        "windows line endings": GOOD_STAGE.replace("\n", "\r\n"),
    }
    refused = []
    for name, text in cases.items():
        sample = tmp / "Dockerfile.sample"
        sample.write_bytes(text.encode("utf-8"))
        found = problems(sample)
        if found:
            refused.append(f"{name}: {found}")
    assert not refused, "refused: " + "; ".join(refused)


def test_the_package_name_is_stripped_of_its_version() -> None:
    strip = re.compile(r"-[0-9][^-]*-r[0-9]+$")
    cases = {
        "libpng-1.6.59-r0": "libpng",
        "go-1.26-1.26.9-r0": "go-1.26",
        "python-3.13-3.13.16-r2": "python-3.13",
        "libpng16-16-1.6.59-r3": "libpng16-16",
        "ca-certificates-bundle-20251003-r0": "ca-certificates-bundle",
    }
    for given, expected in cases.items():
        assert strip.sub("", given) == expected, f"{given} -> {strip.sub('', given)}"


def main() -> int:
    import inspect
    import tempfile

    failed = 0
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    for name, func in tests:
        try:
            if inspect.signature(func).parameters:
                with tempfile.TemporaryDirectory() as tmp:
                    func(Path(tmp))
            else:
                func()
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {name}: {exc}")
        else:
            print(f"ok   {name}")
    print(f"{len(tests) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
