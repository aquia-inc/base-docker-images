#!/usr/bin/env python3
"""Decide a pull request's required build check for one platform.

Branch protection on main requires "publish_image (linux/amd64)" and
"publish_image (linux/arm64)". A pull request builds one leg per selected image
and platform, named "publish_image (<image>, <platform>)", and the pr_gate job
reports the required names from this script's verdict.

The gate passes only when, for its platform, every selected image has exactly
one leg and that leg succeeded. One exception, by owner ruling (2026-11-20):
a leg of an image whose newest release on main already failed (the "known red"
list, release-inputs.py red) may FAIL without failing the gate. It is still
built and reported, so a pull request can never turn a green image red, and an
image that is already red does not block every other change. A cancelled,
skipped, timed-out or unfinished leg, a missing leg and a duplicated leg always
fail, whatever the image.

Usage:
  pr-gate.py <jobs.json> <platform> <images JSON> <known-red JSON>

<jobs.json> is this run's job listing from the Actions API
(GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs?filter=latest&per_page=100).
<images JSON> is select_images' list ([""] when nothing was selected).

Exit 0 pass, 1 fail, 2 bad input (which also fails the check).
"""

from __future__ import annotations

import json
import re
import sys

PLATFORMS = ("linux/amd64", "linux/arm64")
PLAIN_IMAGE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
NO_IMAGE = "no image changed"


class InputError(Exception):
    pass


def image_list(text: str, what: str, allow_none: bool) -> list[str]:
    try:
        value = json.loads(text)
    except ValueError as error:
        raise InputError(f"{what} is not JSON: {error}") from error
    if not isinstance(value, list):
        raise InputError(f"{what} is not a list")
    if allow_none and value == [""]:
        return []
    for name in value:
        if not isinstance(name, str) or not PLAIN_IMAGE.fullmatch(name) or ".." in name:
            raise InputError(f"{what}: not a plain image name: {name!r}")
    return value


def evaluate(jobs: list[dict], platform: str, images: list[str], known_red: list[str],
             log=sys.stdout) -> bool:
    images = [image for image in images if image]
    expected = ([(image, f"publish_image ({image}, {platform})") for image in images]
                or [(None, f"publish_image ({NO_IMAGE}, {platform})")])
    by_name: dict[str, list[dict]] = {}
    for job in jobs:
        by_name.setdefault(job.get("name") or "", []).append(job)
    passed = True
    for image, name in expected:
        legs = by_name.get(name, [])
        if len(legs) != 1:
            print(f"::error::{name}: expected exactly one leg, found {len(legs)}", file=log)
            passed = False
            continue
        status, conclusion = legs[0].get("status"), legs[0].get("conclusion")
        if status == "completed" and conclusion == "success":
            print(f"ok      {name}", file=log)
        elif status == "completed" and conclusion == "failure" and image in known_red:
            print(f"::warning::{name} failed, not gating: {image}'s newest release on main "
                  "already failed", file=log)
        else:
            print(f"::error::{name}: {status}/{conclusion}", file=log)
            passed = False
    return passed


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    path, platform, images_text, red_text = argv
    try:
        if platform not in PLATFORMS:
            raise InputError(f"unknown platform {platform!r}")
        images = image_list(images_text, "images", allow_none=True)
        known_red = image_list(red_text, "known-red list", allow_none=False)
        try:
            with open(path, encoding="utf-8") as handle:
                listing = json.load(handle)
        except (OSError, ValueError) as error:
            raise InputError(f"unreadable job listing {path}: {error}") from error
        jobs = listing.get("jobs") if isinstance(listing, dict) else None
        if not isinstance(jobs, list) or listing.get("total_count") != len(jobs):
            # A second page could hold a failed leg: never judge a partial listing.
            raise InputError("the job listing is not one complete page")
    except InputError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 2
    return 0 if evaluate(jobs, platform, images, known_red) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
