#!/usr/bin/env python3
"""Plan GHCR retention for this repository's images, and apply it on request.

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

By default this script only plans. It reads the GitHub Packages API and the
registry, prints a summary, and writes a JSON report of every decision and its
reason. It never retags anything.

With --apply it also deletes what the plan deletes, and refuses to start
unless every guard holds:

  * the date is on or after EFFECTIVE_DATE, the date the README announces;
  * the safety invariants hold for every package, including that each keeps
    at least min(RELEASES, its release count) releases;
  * the plan deletes no more than --expect-at-most versions, a number the
    operator takes from a report run, so a planner fault that suddenly
    selects far more is refused rather than carried out.

Deletion works in groups: a release with its child manifests and the
signatures and attestations that reference them. Within a group children go
first and the tagged release last, so a run that stops partway leaves the
release tagged and the next run finishes it; deleting the parent first would
strand its children as untagged orphans that no later plan reaches. A group
that still carries a tracking tag waits until that tag is retired. Each
version's tags are re-read just before its package is processed, and a group
whose tags changed since the plan is skipped. Deletions are serial, paced,
capped per run (--max-delete) and stop at the API rate-limit floor or after
consecutive failures. Every deletion is logged with its version id: GitHub
can restore a deleted version for 30 days.

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
    GH_TOKEN=<token with admin on the packages> scripts/ghcr-retention.py \
        --apply --expect-at-most N [--max-delete 400] [--deletion-log F]
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import datetime as dt
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

API = "https://api.github.com"
REGISTRY = "ghcr.io"

# Tags that are never removed, whatever version they sit on: the tracking
# tag every consumer is told to use, the frozen 2 / 2.0 / 2.0.0 cutover
# markers, and the retired FIPS 140-2 tags. Those now hold end-of-life marker
# images; deleting one would turn an explained failure into MANIFEST_UNKNOWN.
ALWAYS_KEEP = {"latest", "openssl3", "openssl3.0", "2", "2.0", "2.0.0"}

# The README announces deletion from this date; --apply refuses before it.
EFFECTIVE_DATE = dt.date(2026, 10, 26)

# Deletion pacing. The repository's GITHUB_TOKEN has about 1000 REST requests
# an hour, shared with every other workflow, and GitHub asks for mutating
# requests to be serial and at least a second apart. A run stops on its own
# when the remaining budget falls to RATE_FLOOR, and after MAX_CONSECUTIVE
# failures in a row, which is what a missing admin role looks like.
DELETE_SPACING_SECONDS = 1.0
RATE_FLOOR = 100
MAX_CONSECUTIVE = 5
MAX_RATE_WAIT_SECONDS = 900

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


def check_invariants(plan: Plan, versions: list[Version],
                     releases: dict[str, set[str]] | None = None,
                     keep_releases: int | None = None) -> list[str]:
    """Return every violation of the safety rules (empty when safe).

    With `releases` and `keep_releases`, also require that the package keeps
    at least min(keep_releases, its release count) releases - the floor the
    README promises, checked independently of how the plan arrived at it.
    """
    problems = []
    overlap = set(plan.keep) & set(plan.delete)
    if overlap:
        problems.append(f"{plan.package}: {len(overlap)} digests both kept and deleted")
    for v in versions:
        for t in v.tags:
            if t in ALWAYS_KEEP and v.digest not in plan.keep:
                problems.append(f"{plan.package}:{t} would not be kept")
    if releases is not None and keep_releases is not None:
        tagged = [v for v in versions if any(is_release(t, plan.image, releases) for t in v.tags)]
        kept = sum(1 for v in tagged if v.digest in plan.keep)
        floor = min(keep_releases, len(tagged))
        if kept < floor:
            problems.append(f"{plan.package}: keeps {kept} releases, fewer than {floor}")
    return problems


# ---------------------------------------------------------------------------
# Deletion (pure decisions; the one DELETE request is delete_version below)
# ---------------------------------------------------------------------------

@dataclass
class Group:
    """Versions deleted together, in order: children first, anchor last."""
    anchor: str
    order: list[str]
    held: list[str] = field(default_factory=list)   # tags that make it wait


def blocking_tags(v: Version, image: str, releases: dict[str, set[str]]) -> list[str]:
    """Tags that keep a version from being deleted yet: anything that is not a
    release or signature tag, i.e. a tracking tag that has not been retired."""
    return [t for t in v.tags if not is_release(t, image, releases) and not SIGNATURE.match(t)]


def deletion_groups(plan: Plan, versions: list[Version], children: dict[str, list[str]],
                    releases: dict[str, set[str]]) -> list[Group]:
    """Partition plan.delete into ordered groups, oldest release first.

    A release's group holds its child closure and every signature (with its
    own children) whose subject is in that closure. Signatures of subjects
    that no longer exist form groups of their own.
    """
    by_digest = {v.digest: v for v in versions}
    claimed: set[str] = set()

    def post_order(start: str) -> list[str]:
        out: list[str] = []
        stack = [(start, False)]
        while stack:
            digest, expanded = stack.pop()
            if expanded:
                out.append(digest)
                continue
            if digest in claimed or digest not in plan.delete:
                continue
            claimed.add(digest)
            stack.append((digest, True))
            stack.extend((child, False) for child in children.get(digest, []))
        return out

    subject_of: dict[str, str] = {}
    for v in versions:
        if v.digest in plan.delete:
            subjects = [m.group(1) for t in v.tags if (m := SIGNATURE.match(t))]
            if subjects:
                subject_of[v.digest] = "sha256:" + subjects[0]

    def held(order: list[str]) -> list[str]:
        return sorted({t for d in order if d in by_digest
                       for t in blocking_tags(by_digest[d], plan.image, releases)})

    groups: list[Group] = []
    roots = sorted((by_digest[d] for d in plan.delete if d in by_digest
                    and any(is_release(t, plan.image, releases) for t in by_digest[d].tags)),
                   key=lambda v: (v.created, v.id))
    for root in roots:
        main = post_order(root.digest)
        closure = set(main)
        signatures: list[str] = []
        for sig in sorted(subject_of):
            if subject_of[sig] in closure:
                signatures += post_order(sig)
        order = signatures + main
        groups.append(Group(root.digest, order, held(order)))
    for sig in sorted(subject_of):
        order = post_order(sig)
        if order:
            groups.append(Group(sig, order, held(order)))
    for digest in sorted(plan.delete):
        order = post_order(digest)
        if order:
            groups.append(Group(digest, order, held(order)))
    return groups


def apply_refusals(today: dt.date, problems: list[str], planned: int,
                   expect_at_most: int) -> list[str]:
    """Every reason not to start deleting (empty means go)."""
    refusals = []
    if today < EFFECTIVE_DATE:
        refusals.append(f"today {today} is before the announced date {EFFECTIVE_DATE}")
    if problems:
        refusals.append(f"{len(problems)} safety invariant(s) fail")
    if expect_at_most <= 0:
        refusals.append("--expect-at-most must be a positive number taken from a report run")
    elif planned > expect_at_most:
        refusals.append(f"the plan deletes {planned} versions, more than --expect-at-most "
                        f"{expect_at_most}")
    return refusals


@dataclass
class Outcome:
    attempted: int = 0
    stopped: str = ""      # why the run stopped early, empty when it did not
    failed: bool = False   # stopped by consecutive failures rather than by budget
    log: list[dict] = field(default_factory=list)


def run_deletions(package: str, groups: list[Group], planned_tags: dict[str, list[str]],
                  current: dict[str, tuple[int, list[str]]], deleter, budget: int,
                  outcome: Outcome, sleep=time.sleep, now=time.time) -> None:
    """Delete eligible groups of one package until the budget is spent.

    `planned_tags` is digest -> tags at planning time; `current` is digest ->
    (version id, tags) re-read just before this call. `deleter(version_id)`
    returns (status, headers, detail). Whole groups only: a group is never
    started once `outcome.attempted` reaches `budget`.
    """
    consecutive = 0
    for group in groups:
        if outcome.stopped or outcome.attempted >= budget:
            return
        if group.held:
            continue
        if any(d in current and sorted(current[d][1]) != sorted(planned_tags.get(d, []))
               for d in group.order):
            outcome.log.append({"package": package, "digest": group.anchor,
                                "result": "skipped", "detail": "tags changed since the plan"})
            continue
        for digest in group.order:
            if digest not in current:
                continue  # already gone, or never a version of this package
            version_id = current[digest][0]
            waits = 0
            while True:
                if outcome.attempted:
                    sleep(DELETE_SPACING_SECONDS)
                outcome.attempted += 1
                status, headers, detail = deleter(version_id)
                wait = rate_limit_wait(status, headers, now())
                if wait is None and (status == 0 or status >= 500):
                    wait = float(2 ** (waits + 1))  # dropped connection or server error
                if wait is None or waits >= 3:
                    break
                waits += 1
                sleep(wait)
            entry = {"package": package, "id": version_id, "digest": digest,
                     "group": group.anchor, "status": status}
            done = status in (200, 202, 204, 404)
            if done:
                entry["result"] = "deleted" if status != 404 else "already gone"
                consecutive = 0
            else:
                entry["result"], entry["detail"] = "refused", detail
                consecutive += 1
            outcome.log.append(entry)
            if consecutive >= MAX_CONSECUTIVE:
                outcome.stopped = f"{consecutive} consecutive failures, last HTTP {status}: {detail}"
                outcome.failed = True
                return
            remaining = {k.lower(): v for k, v in headers.items()}.get("x-ratelimit-remaining", "")
            if remaining.isdigit() and int(remaining) <= RATE_FLOOR:
                outcome.stopped = f"API rate budget at {remaining}; the next run continues"
                return
            if not done:
                # Leave the rest of the group, its tagged release included, for
                # a later run: deleting the parent of a child that could not be
                # deleted would strand that child as an orphan no plan reaches.
                break


def rate_limit_wait(status: int, headers: dict[str, str], now: float) -> float | None:
    """Seconds to wait before retrying a rate-limited request, else None."""
    if status not in (403, 429):
        return None
    lower = {k.lower(): v for k, v in headers.items()}
    if lower.get("retry-after", "").isdigit():
        return min(float(lower["retry-after"]), MAX_RATE_WAIT_SECONDS)
    if lower.get("x-ratelimit-remaining") == "0" and lower.get("x-ratelimit-reset", "").isdigit():
        return min(max(float(lower["x-ratelimit-reset"]) - now, 1.0), MAX_RATE_WAIT_SECONDS)
    return None


def retirements(plans: list[Plan]) -> list[dict[str, str]]:
    """Stale tracking tags to retire, one entry per image and tag.

    Each entry carries the digest the tag was seen on in the multi-arch and
    both per-arch packages ("-" where the tag was not seen), which
    eol/retire-tag.sh requires to be unchanged before it pushes a marker.
    """
    seen: dict[tuple[str, str], dict[str, str]] = {}
    for plan in plans:
        suffix = plan.package[len(plan.image):]
        key = {"": "digest", "-linux-amd64": "amd64", "-linux-arm64": "arm64"}.get(suffix)
        if key is None:
            continue
        for tag, digest in plan.retire.items():
            if tag in ALWAYS_KEEP:
                continue
            entry = seen.setdefault((plan.image, tag), {
                "image": plan.image, "tag": tag, "digest": "-", "amd64": "-", "arm64": "-"})
            entry[key] = digest
    return [seen[k] for k in sorted(seen)]


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------

# Credential material this process has handled, scrubbed from any text that
# might reach a log before it is raised.
#
# This matters more for the registry's bearer token than for the configured
# one. GitHub Actions masks a secret it injected, so an accidental echo of
# GH_TOKEN appears as ***; the registry token is minted at runtime from that
# secret and the log filter has never seen it, so it would be published in
# full. Both are registered here, along with the base64 Basic form, because
# base64 is an encoding and not a protection.
_SECRETS: set[str] = set()


def remember_secret(secret: str | None) -> None:
    """Register a credential so redact() will scrub it."""
    if not secret or len(secret) < 8:
        return
    _SECRETS.add(secret)
    _SECRETS.add(base64.b64encode(f"x:{secret}".encode()).decode())


def redact(text: str) -> str:
    """Remove every registered credential from text."""
    for secret in _SECRETS:
        text = text.replace(secret, "<redacted>")
    return text


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


# The API occasionally drops a connection or answers 5xx partway through a
# multi-page walk, and one such blip failed a whole report. Every request here
# is a GET, so a short bounded retry is safe. A 4xx is never retried: it will
# not change on its own, and retrying would only hide it.
RETRIES = 3
RETRY_STATUS = {500, 502, 503, 504}
_sleep = time.sleep


def http_json(url: str, headers: dict[str, str]) -> tuple[object, dict[str, str]]:
    for attempt in range(RETRIES + 1):
        try:
            return _http_json_once(url, headers)
        except urllib.error.HTTPError as error:
            if error.code not in RETRY_STATUS or attempt == RETRIES:
                raise
            reason = f"HTTP {error.code}"
        except (urllib.error.URLError, http.client.HTTPException,
                ConnectionError, TimeoutError) as error:
            if attempt == RETRIES:
                raise
            reason = type(error).__name__
        delay = 2 ** (attempt + 1)
        print(f"retry {attempt + 1}/{RETRIES} in {delay}s after {reason}: {redact(url)}",
              file=sys.stderr)
        _sleep(delay)
    raise AssertionError("unreachable")


def _http_json_once(url: str, headers: dict[str, str]) -> tuple[object, dict[str, str]]:
    request = urllib.request.Request(url, headers=headers)
    try:
        with _OPENER.open(request, timeout=60) as response:
            return json.load(response), dict(response.headers)
    except urllib.error.HTTPError as error:
        # Keep GitHub's explanation: a bare "400 Bad Request" is undiagnosable.
        # Both the body and the URL are scrubbed first - a server is free to
        # echo what it was sent, and this error text ends up in CI logs.
        detail = redact(error.read(500).decode("utf-8", "replace"))
        raise urllib.error.HTTPError(redact(error.url), error.code,
                                     f"{error.reason}: {detail}", error.headers, None) from None


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


def candidate_packages(releases: dict[str, set[str]]) -> list[str]:
    """Every package this repository can have published.

    Derived from the release tags rather than by listing the organisation's
    packages, which the workflow's GITHUB_TOKEN is not allowed to do. Each
    released image publishes a multi-arch package plus one per architecture;
    packages that do not exist are skipped by the caller.
    """
    return sorted(f"{image}{suffix}" for image in releases
                  for suffix in ("", "-linux-amd64", "-linux-arm64"))


def package_versions(org: str, repo: str, package: str, token: str) -> list[Version]:
    name = urllib.parse.quote(f"{repo}/{package}", safe="")
    return [Version(id=v["id"], digest=v["name"],
                    created=dt.date.fromisoformat(v["created_at"][:10]),
                    tags=v["metadata"]["container"]["tags"])
            for v in api_pages(f"/orgs/{org}/packages/container/{name}/versions", token)]


def index_children(org: str, repo: str, package: str, digests: list[str],
                   token: str | None = None) -> dict[str, list[str]]:
    """Fetch each manifest and return the digests it references.

    The registry pull token is requested WITH credentials when one is
    available. An anonymous token only works while every package is public, and
    a private one answers 401 "authentication required" - which reads as a
    broken script rather than a visibility difference, and surfaces only on
    whichever package happens to be private and sorts first.
    """
    scope = f"repository:{org}/{repo}/{package}:pull"
    token_headers = {}
    if token:
        # The registry's token endpoint takes HTTP Basic; GHCR ignores the
        # username and reads only the password.
        basic = base64.b64encode(f"x:{token}".encode()).decode()
        token_headers["Authorization"] = "Basic " + basic
    token_data, _ = http_json(
        f"https://{REGISTRY}/token?scope={urllib.parse.quote(scope)}", token_headers)
    # Registered before use: this one is minted here, so nothing upstream knows
    # to mask it if it ends up in a traceback.
    remember_secret(token_data.get("token"))
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


def delete_version(org: str, repo: str, package: str, version_id: int,
                   token: str) -> tuple[int, dict[str, str], str]:
    """Delete one package version. The only request in this file that deletes.

    Returns (HTTP status, response headers, redacted detail) rather than
    raising, so the caller decides what a refusal means. A version id is
    always an integer from the API; it is formatted as one so nothing else
    can reach the path.
    """
    name = urllib.parse.quote(f"{repo}/{package}", safe="")
    url = f"{API}/orgs/{org}/packages/container/{name}/versions/{int(version_id)}"
    request = urllib.request.Request(url, method="DELETE", headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with _OPENER.open(request, timeout=60) as response:
            return response.status, dict(response.headers), ""
    except urllib.error.HTTPError as error:
        detail = redact(error.read(300).decode("utf-8", "replace"))
        return error.code, dict(error.headers or {}), detail
    except (urllib.error.URLError, http.client.HTTPException,
            ConnectionError, TimeoutError) as error:
        return 0, {}, redact(f"{type(error).__name__}: {error}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--org", default="aquia-inc")
    parser.add_argument("--repo", default="base-docker-images")
    parser.add_argument("--releases", type=int, default=30)
    parser.add_argument("--days", type=int, default=90)
    parser.add_argument("--today", type=dt.date.fromisoformat, default=None)
    parser.add_argument("--report", default="retention-report.json")
    parser.add_argument("--apply", action="store_true",
                        help="delete what the plan deletes, under the guards above")
    parser.add_argument("--expect-at-most", type=int, default=0,
                        help="refuse to delete when the plan deletes more than this")
    parser.add_argument("--max-delete", type=int, default=400,
                        help="delete requests per run; whole groups only")
    parser.add_argument("--deletion-log", default="deletion-log.json")
    parser.add_argument("--retire-list",
                        help="with --apply, write the stale tags to retire (eol/retire-tag.sh)")
    args = parser.parse_args()
    if args.apply and args.today is not None:
        parser.error("--today cannot be combined with --apply: deletion uses the real date")
    if args.max_delete < 1:
        parser.error("--max-delete must be at least 1")
    utc_today = dt.datetime.now(dt.timezone.utc).date()
    today = args.today or utc_today

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        sys.exit("ghcr-retention: set GH_TOKEN to a token with read:packages")
    remember_secret(token)

    releases = release_tags(args.org, args.repo, token)

    report, problems, planned = [], [], []
    header = f"{'package':28} {'versions':>8} {'keep':>6} {'delete':>6} {'retire':>6} {'orphans':>7} {'unknown':>7}"
    print(f"Retention plan: newest {args.releases} releases or under {args.days} days, as of {today}")
    print("APPLY - the plan below is carried out if every guard holds.\n" if args.apply
          else "REPORT ONLY - nothing is deleted or retagged.\n")
    print(header)
    totals = [0] * 6
    for package in candidate_packages(releases):
        try:
            versions = package_versions(args.org, args.repo, package, token)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                continue  # this image never published that variant
            raise
        # Every tagged version is fetched, signature tags included: those can
        # be indexes whose children are live attestation bundles.
        tagged = [v.digest for v in versions if v.tags]
        children = index_children(args.org, args.repo, package, tagged, token)
        plan = plan_package(package, versions, children, releases, today,
                            args.releases, args.days)
        problems += check_invariants(plan, versions, releases, args.releases)
        planned.append((package, versions, plan,
                        deletion_groups(plan, versions, children, releases)))
        orphan_groups = classify_orphans(
            plan, index_children(args.org, args.repo, package, plan.orphans, token))
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

    ready = sum(len(g.order) for _, _, _, groups in planned for g in groups if not g.held)
    waiting = [g for _, _, _, groups in planned for g in groups if g.held]
    print(f"\nDeletable now: {ready} versions. Waiting for a tracking tag to be retired: "
          f"{sum(len(g.order) for g in waiting)} versions in {len(waiting)} groups.")

    with open(args.report, "w", encoding="utf-8") as handle:
        json.dump({"policy": {"releases": args.releases, "days": args.days,
                              "today": today.isoformat()},
                   "packages": report, "problems": problems}, handle, indent=1)
    print(f"\nFull report: {args.report}")

    if problems:
        print("\nSAFETY CHECK FAILED:")
        for problem in problems:
            print("  " + problem)
        return 1
    if not args.apply:
        return 0

    total_delete = sum(len(plan.delete) for _, _, plan, _ in planned)
    refusals = apply_refusals(utc_today, problems, total_delete, args.expect_at_most)
    if refusals:
        print("\nNOT DELETING:")
        for refusal in refusals:
            print("  " + refusal)
        return 2

    if args.retire_list:
        retire_entries = retirements([plan for _, _, plan, _ in planned])
        with open(args.retire_list, "w", encoding="utf-8") as handle:
            json.dump(retire_entries, handle, indent=1)
        print(f"\nRetire list: {len(retire_entries)} tags in {args.retire_list}")

    outcome = Outcome()
    try:
        for package, versions, _, groups in planned:
            if outcome.stopped or outcome.attempted >= args.max_delete:
                break
            if not any(not g.held for g in groups):
                continue
            # Re-read just before deleting, so a version whose tags changed
            # since the plan (or that is already gone) is never acted on.
            current = {v.digest: (v.id, v.tags)
                       for v in package_versions(args.org, args.repo, package, token)}
            run_deletions(package, groups, {v.digest: v.tags for v in versions}, current,
                          lambda vid, p=package: delete_version(args.org, args.repo, p, vid, token),
                          args.max_delete, outcome)
    finally:
        with open(args.deletion_log, "w", encoding="utf-8") as handle:
            json.dump({"date": utc_today.isoformat(), "attempted": outcome.attempted,
                       "stopped": outcome.stopped, "entries": outcome.log}, handle, indent=1)

    results: dict[str, int] = {}
    for entry in outcome.log:
        results[entry["result"]] = results.get(entry["result"], 0) + 1
    print(f"\nDeletion: {outcome.attempted} requests; "
          + ", ".join(f"{n} {r}" for r, n in sorted(results.items()))
          + f". Log (version ids, restorable for 30 days): {args.deletion_log}")
    if outcome.stopped:
        print(f"Stopped early: {outcome.stopped}")
    return 1 if outcome.failed else 0


if __name__ == "__main__":
    sys.exit(main())
