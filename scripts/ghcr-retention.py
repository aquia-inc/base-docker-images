#!/usr/bin/env python3
"""Plan GHCR retention for this repository's images. Reports only.

Policy (README "Image Retention", announced in #758):

  * Each image keeps its newest RELEASES releases and every release younger
    than DAYS days, whichever keeps more.
  * `latest`, the frozen and retired tags listed in ALWAYS_KEEP, and any
    tracking tag that is still moving are never removed.
  * A tracking tag whose version line has ended (for example
    `nodejs-base:24.9` after 24.10 shipped) stops moving and keeps pointing at
    an image that is never patched again. Once that image falls outside the
    window the tag is RETIRED - replaced by an end-of-life marker naming the
    current tag - and the release is then deleted like any other.
  * A deleted release takes its child manifests (per-platform images,
    attestation manifests) and its cosign signatures/attestations with it.

This script only plans. It reads the GitHub Packages API and the registry,
prints a summary, and writes a JSON report of every decision and its reason.
It never deletes or retags anything.

Two traps shape the implementation:

  * "Untagged" does not mean "orphaned". Every per-arch tag points at an index
    whose child manifests are listed by GHCR as separate untagged versions.
    Children are therefore found by walking the indexes of kept versions, and
    anything a kept index references is kept.
  * Not every X.Y.Z tag is a release. Early releases had no "v" prefix, while
    tags such as `python-base:3.13.11` are language versions. A tag counts as
    a release only if the git tag `release/<image>/[v]X.Y.Z` exists.

Usage:
    GH_TOKEN=<token with read:packages> scripts/ghcr-retention.py \
        [--releases 30] [--days 90] [--report retention-report.json]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

API = "https://api.github.com"
REGISTRY = "ghcr.io"

# Tags that are never removed, whatever version they sit on: the tracking
# tag every consumer is told to use, and the FIPS tags that are frozen or
# already retired to an end-of-life marker (see FIPS.md).
ALWAYS_KEEP = {"latest", "openssl3", "openssl3.0", "2", "2.0", "2.0.0"}

RELEASE_SHAPE = re.compile(r"^v?\d+\.\d+\.\d+$")
SIGNATURE = re.compile(r"^sha256-([0-9a-f]{64})(\.sig|\.att|\.sbom)?$")
ARCH_SUFFIX = re.compile(r"-linux-(amd64|arm64)$")

MANIFEST_ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


# ---------------------------------------------------------------------------
# Planning (pure: no I/O, unit-tested)
# ---------------------------------------------------------------------------

@dataclass
class Version:
    id: int
    digest: str
    created: dt.date
    tags: list[str]


@dataclass
class Plan:
    package: str
    image: str
    keep: dict[str, str] = field(default_factory=dict)      # digest -> reason
    delete: dict[str, str] = field(default_factory=dict)    # digest -> reason
    retire: dict[str, str] = field(default_factory=dict)    # tag -> digest
    orphans: list[str] = field(default_factory=list)
    unknown: dict[str, list[str]] = field(default_factory=dict)


def image_of(package: str) -> str:
    return ARCH_SUFFIX.sub("", package)


def is_release(tag: str, image: str, releases: dict[str, set[str]]) -> bool:
    return bool(RELEASE_SHAPE.match(tag)) and tag.lstrip("v") in releases.get(image, set())


def plan_package(package: str, versions: list[Version], children: dict[str, list[str]],
                 releases: dict[str, set[str]], today: dt.date,
                 keep_releases: int, keep_days: int) -> Plan:
    """Decide keep / delete / retire for every version of one package.

    `children` maps an index digest to the digests it references (empty or
    missing for a plain image manifest).
    """
    image = image_of(package)
    plan = Plan(package=package, image=image)

    release_versions = sorted(
        (v for v in versions if any(is_release(t, image, releases) for t in v.tags)),
        key=lambda v: v.created, reverse=True)
    in_window = {v.digest for i, v in enumerate(release_versions)
                 if i < keep_releases or (today - v.created).days < keep_days}

    roots_keep: dict[str, str] = {}
    roots_delete: dict[str, str] = {}
    for v in versions:
        other = [t for t in v.tags
                 if not is_release(t, image, releases) and not SIGNATURE.match(t)]
        if any(t in ALWAYS_KEEP for t in other):
            roots_keep[v.digest] = "always-keep tag: " + ",".join(
                t for t in other if t in ALWAYS_KEEP)
        elif v.digest in in_window:
            roots_keep[v.digest] = "release in window"
        elif any(is_release(t, image, releases) for t in v.tags):
            # Out-of-window release. Tracking tags still on it have stopped
            # moving (the moving ones sit on newer releases): retire them.
            for t in other:
                plan.retire[t] = v.digest
            roots_delete[v.digest] = ("out-of-window release"
                                      + (" (retire stale tags first: " + ",".join(other) + ")"
                                         if other else ""))
        elif other:
            # A tagged version that is not a release and carries no
            # always-keep tag, e.g. fips-base:fips3 mirrored from fips-140-3.
            # Keep it and report it rather than guess.
            roots_keep[v.digest] = "non-release tag: " + ",".join(other)
            plan.unknown[v.digest] = other

    def walk(roots: dict[str, str]) -> dict[str, str]:
        seen: dict[str, str] = {}
        stack = list(roots.items())
        while stack:
            digest, reason = stack.pop()
            if digest in seen:
                continue
            seen[digest] = reason
            for child in children.get(digest, []):
                stack.append((child, "child of " + digest[:19]))
        return seen

    keep = walk(roots_keep)
    delete = {d: r for d, r in walk(roots_delete).items() if d not in keep}

    # Signatures and attestations follow their subject. A `sha256-<hex>` tag
    # can itself be an index (the OCI referrers-tag scheme) listing sigstore
    # bundle manifests, so each signature is walked like a release and its
    # children follow its decision.
    by_digest = {v.digest: v for v in versions}
    sig_keep: dict[str, str] = {}
    sig_delete: dict[str, str] = {}
    for v in versions:
        subjects = [m.group(1) for t in v.tags if (m := SIGNATURE.match(t))]
        if not subjects or v.digest in keep or v.digest in delete:
            continue
        subject = "sha256:" + subjects[0]
        if subject in keep:
            sig_keep[v.digest] = "signature of kept " + subject[:19]
        elif subject in delete:
            sig_delete[v.digest] = "signature of deleted " + subject[:19]
        elif subject not in by_digest:
            sig_delete[v.digest] = "signature of absent " + subject[:19]
        else:
            sig_keep[v.digest] = "signature (subject undecided, kept)"
    for digest, reason in walk(sig_keep).items():
        keep.setdefault(digest, reason)
    for digest, reason in walk(sig_delete).items():
        if digest not in keep:
            delete.setdefault(digest, reason)
    for digest in keep:
        delete.pop(digest, None)

    for v in versions:
        if v.digest not in keep and v.digest not in delete:
            if v.tags:
                keep[v.digest] = "unclassified tags (kept): " + ",".join(v.tags)
                plan.unknown[v.digest] = v.tags
            else:
                plan.orphans.append(v.digest)

    plan.keep, plan.delete = keep, delete
    return plan


def classify_orphans(plan: Plan, orphan_children: dict[str, list[str]]) -> dict[str, list[str]]:
    """Split orphans into superseded indexes and unreferenced leftovers.

    Rewriting a referrers-tag index (for example when an attestation is added)
    leaves the previous revision behind untagged. Its children are still
    listed by the current index, so it is safe but useless. Everything else
    is simply unreferenced.
    """
    groups: dict[str, list[str]] = {"superseded-index": [], "unreferenced": []}
    for digest in plan.orphans:
        kids = orphan_children.get(digest, [])
        if kids and all(k in plan.keep for k in kids):
            groups["superseded-index"].append(digest)
        else:
            groups["unreferenced"].append(digest)
    return groups


def check_invariants(plan: Plan, versions: list[Version]) -> list[str]:
    """Return every violation of the safety rules (empty when safe)."""
    problems = []
    overlap = set(plan.keep) & set(plan.delete)
    if overlap:
        problems.append(f"{plan.package}: {len(overlap)} digests both kept and deleted")
    for v in versions:
        for t in v.tags:
            if t in ALWAYS_KEEP and v.digest not in plan.keep:
                problems.append(f"{plan.package}:{t} would not be kept")
    return problems


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------

def _https_only_opener() -> urllib.request.OpenerDirector:
    """An opener with no handler for file://, ftp:// or plain http://.

    URLs come from the API's pagination links and the registry, so the scheme
    is restricted structurally rather than trusted: anything other than https,
    including a redirect to http, fails with "unknown url type".
    """
    opener = urllib.request.OpenerDirector()
    for handler in (urllib.request.HTTPSHandler(), urllib.request.HTTPRedirectHandler(),
                    urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor(),
                    urllib.request.UnknownHandler()):
        opener.add_handler(handler)
    return opener


_OPENER = _https_only_opener()


def http_json(url: str, headers: dict[str, str]) -> tuple[object, dict[str, str]]:
    request = urllib.request.Request(url, headers=headers)
    with _OPENER.open(request, timeout=60) as response:
        return json.load(response), dict(response.headers)


def api_pages(path: str, token: str) -> list:
    headers = {"Authorization": "Bearer " + token,
               "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    url = f"{API}{path}{'&' if '?' in path else '?'}per_page=100"
    items: list = []
    while url:
        data, response_headers = http_json(url, headers)
        items.extend(data if isinstance(data, list) else [data])
        url = ""
        for part in response_headers.get("Link", "").split(","):
            if 'rel="next"' in part:
                url = part[part.index("<") + 1:part.index(">")]
    return items


def release_tags(org: str, repo: str, token: str) -> dict[str, set[str]]:
    releases: dict[str, set[str]] = {}
    for ref in api_pages(f"/repos/{org}/{repo}/git/matching-refs/tags/release/", token):
        _, _, rest = ref["ref"].partition("refs/tags/release/")
        image, _, version = rest.partition("/")
        releases.setdefault(image, set()).add(version.lstrip("v").split("+")[0])
    return releases


def package_versions(org: str, repo: str, package: str, token: str) -> list[Version]:
    name = urllib.parse.quote(f"{repo}/{package}", safe="")
    return [Version(id=v["id"], digest=v["name"],
                    created=dt.date.fromisoformat(v["created_at"][:10]),
                    tags=v["metadata"]["container"]["tags"])
            for v in api_pages(f"/orgs/{org}/packages/container/{name}/versions", token)]


def index_children(org: str, repo: str, package: str,
                   digests: list[str]) -> dict[str, list[str]]:
    """Fetch each manifest and return the digests it references."""
    scope = f"repository:{org}/{repo}/{package}:pull"
    token_data, _ = http_json(f"https://{REGISTRY}/token?scope={urllib.parse.quote(scope)}", {})
    headers = {"Authorization": "Bearer " + token_data["token"], "Accept": MANIFEST_ACCEPT}

    def fetch(digest: str) -> tuple[str, list[str]]:
        url = f"https://{REGISTRY}/v2/{org}/{repo}/{package}/manifests/{digest}"
        try:
            manifest, _ = http_json(url, headers)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return digest, []
            raise
        return digest, [m["digest"] for m in manifest.get("manifests", [])]

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        return dict(pool.map(fetch, digests))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--org", default="aquia-inc")
    parser.add_argument("--repo", default="base-docker-images")
    parser.add_argument("--releases", type=int, default=30)
    parser.add_argument("--days", type=int, default=90)
    parser.add_argument("--today", type=dt.date.fromisoformat, default=dt.date.today())
    parser.add_argument("--report", default="retention-report.json")
    args = parser.parse_args()

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        sys.exit("ghcr-retention: set GH_TOKEN to a token with read:packages")

    releases = release_tags(args.org, args.repo, token)
    packages = sorted(
        p["name"].split("/", 1)[1]
        for p in api_pages(f"/orgs/{args.org}/packages?package_type=container", token)
        if p.get("repository", {}).get("name") == args.repo and "/" in p["name"])
    if not packages:
        sys.exit("ghcr-retention: no packages found - check the token's package access")

    report, problems = [], []
    header = f"{'package':28} {'versions':>8} {'keep':>6} {'delete':>6} {'retire':>6} {'orphans':>7} {'unknown':>7}"
    print(f"Retention plan: newest {args.releases} releases or under {args.days} days, as of {args.today}")
    print("REPORT ONLY - nothing is deleted or retagged.\n")
    print(header)
    totals = [0] * 6
    for package in packages:
        versions = package_versions(args.org, args.repo, package, token)
        # Every tagged version is fetched, signature tags included: those can
        # be indexes whose children are live attestation bundles.
        tagged = [v.digest for v in versions if v.tags]
        children = index_children(args.org, args.repo, package, tagged)
        plan = plan_package(package, versions, children, releases, args.today,
                            args.releases, args.days)
        problems += check_invariants(plan, versions)
        orphan_groups = classify_orphans(
            plan, index_children(args.org, args.repo, package, plan.orphans))
        row = [len(versions), len(plan.keep), len(plan.delete), len(plan.retire),
               len(plan.orphans), len(plan.unknown)]
        totals = [a + b for a, b in zip(totals, row)]
        print(f"{package:28} " + " ".join(f"{n:>{w}}" for n, w in zip(row, (8, 6, 6, 6, 7, 7))))
        report.append({
            "package": package, "image": plan.image,
            "keep": plan.keep, "delete": plan.delete, "retire": plan.retire,
            "orphans": orphan_groups, "unknown": plan.unknown,
        })
    print(f"{'TOTAL':28} " + " ".join(f"{n:>{w}}" for n, w in zip(totals, (8, 6, 6, 6, 7, 7))))

    superseded = sum(len(r["orphans"]["superseded-index"]) for r in report)
    unreferenced = sum(len(r["orphans"]["unreferenced"]) for r in report)
    print(f"\nOrphans: {superseded} superseded indexes (children still kept elsewhere),"
          f" {unreferenced} unreferenced. Reported only.")

    retire = sorted({(r["image"], t) for r in report for t in r["retire"]})
    if retire:
        print("\nStale tags to retire with an end-of-life marker:")
        for image, tag in retire:
            print(f"  {image}:{tag}")

    with open(args.report, "w", encoding="utf-8") as handle:
        json.dump({"policy": {"releases": args.releases, "days": args.days,
                              "today": args.today.isoformat()},
                   "packages": report, "problems": problems}, handle, indent=1)
    print(f"\nFull report: {args.report}")

    if problems:
        print("\nSAFETY CHECK FAILED:")
        for problem in problems:
            print("  " + problem)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
