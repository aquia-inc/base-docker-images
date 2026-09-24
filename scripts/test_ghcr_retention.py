"""Unit tests for the planning logic in ghcr-retention.py (no network)."""

import datetime as dt
import importlib.util
import pathlib
import sys

_spec = importlib.util.spec_from_file_location(
    "ghcr_retention", pathlib.Path(__file__).with_name("ghcr-retention.py"))
gr = importlib.util.module_from_spec(_spec)
# Registered before executing: dataclasses resolve annotations via sys.modules.
sys.modules[_spec.name] = gr
_spec.loader.exec_module(gr)

TODAY = dt.date(2026, 10, 26)


def d(n: int) -> str:
    return "sha256:" + f"{n:064x}"


def version(n: int, days_old: int, tags: list[str]) -> "gr.Version":
    return gr.Version(id=n, digest=d(n), created=TODAY - dt.timedelta(days=days_old), tags=tags)


def daily_releases(count: int, start_days_old: int = 100):
    """`count` releases one day apart, newest first, each an index with one child."""
    versions, children, releases = [], {}, {"python-base": set()}
    for i in range(count):
        tag = f"v1.1.{count - i}"
        releases["python-base"].add(tag.lstrip("v"))
        index, child = 1000 + i, 5000 + i
        versions.append(version(index, start_days_old + i, [tag]))
        versions.append(version(child, start_days_old + i, []))
        children[d(index)] = [d(child)]
    return versions, children, releases


def plan(versions, children, releases, package="python-base-linux-amd64", n=30, days=90):
    return gr.plan_package(package, versions, children, releases, TODAY, n, days)


def test_keeps_newest_n_when_all_are_old():
    versions, children, releases = daily_releases(35)
    p = plan(versions, children, releases)
    kept = [v for v in versions if v.tags and v.digest in p.keep]
    deleted = [v for v in versions if v.tags and v.digest in p.delete]
    assert len(kept) == 30 and len(deleted) == 5
    assert all(v.created < min(k.created for k in kept) for v in deleted)


def test_keeps_everything_younger_than_window_even_beyond_n():
    versions, children, releases = daily_releases(40, start_days_old=1)
    p = plan(versions, children, releases)
    assert not p.delete


def test_children_follow_their_index():
    versions, children, releases = daily_releases(35)
    p = plan(versions, children, releases)
    for index, kids in children.items():
        for kid in kids:
            assert (index in p.keep) == (kid in p.keep)
            assert (index in p.delete) == (kid in p.delete)


def test_child_shared_with_a_kept_index_is_never_deleted():
    versions, children, releases = daily_releases(35)
    oldest = versions[-2].digest                      # an index that will be deleted
    newest = versions[0].digest                       # an index that will be kept
    children[oldest] = children[oldest] + children[newest]
    p = plan(versions, children, releases)
    assert oldest in p.delete
    assert children[newest][0] in p.keep and children[newest][0] not in p.delete


def test_latest_and_frozen_tags_are_kept_on_old_versions():
    versions, children, releases = daily_releases(35)
    versions[-2].tags.append("latest")
    versions[-4].tags.append("openssl3")
    p = plan(versions, children, releases)
    assert versions[-2].digest in p.keep and versions[-4].digest in p.keep


def test_stale_tracking_tag_on_old_release_is_retired_and_release_deleted():
    versions, children, releases = daily_releases(35)
    versions[-2].tags.append("3.13.11")
    p = plan(versions, children, releases)
    assert p.retire == {"3.13.11": versions[-2].digest}
    assert versions[-2].digest in p.delete


def test_moving_tracking_tag_on_new_release_is_not_retired():
    versions, children, releases = daily_releases(35)
    versions[0].tags += ["3.13", "3"]
    p = plan(versions, children, releases)
    assert not p.retire and versions[0].digest in p.keep


def test_language_version_tag_is_not_mistaken_for_a_release():
    releases = {"python-base": {"1.1.1"}}
    versions = [version(1, 200, ["3.13.11"])]
    p = plan(versions, {}, releases)
    assert d(1) in p.keep and d(1) in p.unknown and not p.delete


def test_legacy_release_without_v_prefix_is_a_release():
    releases = {"python-base": {"1.1.9"}}
    versions = [version(1, 400, ["1.1.9"])]
    p = plan(versions, {}, releases, n=0)
    assert d(1) in p.delete


def test_signatures_follow_their_subject():
    versions, children, releases = daily_releases(35)
    kept_hex = versions[0].digest.split(":")[1]
    gone_hex = versions[-2].digest.split(":")[1]
    versions.append(version(9001, 50, [f"sha256-{kept_hex}.sig"]))
    versions.append(version(9002, 200, [f"sha256-{gone_hex}.att"]))
    versions.append(version(9003, 200, [f"sha256-{gone_hex}"]))
    p = plan(versions, children, releases)
    assert d(9001) in p.keep
    assert d(9002) in p.delete and d(9003) in p.delete


def test_children_of_signature_indexes_follow_the_signature():
    # A referrers-tag index (sha256-<hex>) lists sigstore bundle manifests.
    versions, children, releases = daily_releases(35)
    kept_hex = versions[0].digest.split(":")[1]
    gone_hex = versions[-2].digest.split(":")[1]
    versions += [version(9101, 50, [f"sha256-{kept_hex}"]), version(9102, 50, []),
                 version(9201, 200, [f"sha256-{gone_hex}"]), version(9202, 200, [])]
    children[d(9101)] = [d(9102)]
    children[d(9201)] = [d(9202)]
    p = plan(versions, children, releases)
    assert d(9102) in p.keep and d(9102) not in p.orphans
    assert d(9202) in p.delete and d(9202) not in p.orphans


def test_unreferenced_untagged_version_is_reported_as_orphan_not_deleted():
    versions, children, releases = daily_releases(3, start_days_old=1)
    versions.append(version(7777, 300, []))
    p = plan(versions, children, releases)
    assert p.orphans == [d(7777)] and d(7777) not in p.delete


def test_orphans_split_into_superseded_indexes_and_unreferenced():
    versions, children, releases = daily_releases(3, start_days_old=1)
    versions += [version(8001, 5, []), version(8002, 300, [])]
    p = plan(versions, children, releases)
    kept_child = children[versions[0].digest][0]
    groups = gr.classify_orphans(p, {d(8001): [kept_child]})
    assert groups == {"superseded-index": [d(8001)], "unreferenced": [d(8002)]}


def test_sbom_suffix_counts_as_a_signature():
    assert gr.SIGNATURE.match("sha256-" + "a" * 64 + ".sbom")


def test_candidate_packages_cover_every_released_image_and_arch():
    got = gr.candidate_packages({"fips-base": {"1.1.1"}, "go-base-1.27": {"0.0.1"}})
    assert got == ["fips-base", "fips-base-linux-amd64", "fips-base-linux-arm64",
                   "go-base-1.27", "go-base-1.27-linux-amd64", "go-base-1.27-linux-arm64"]


def test_multi_arch_package_maps_to_its_image():
    assert gr.image_of("nodejs-base-linux-arm64") == "nodejs-base"
    assert gr.image_of("go-base-1.27") == "go-base-1.27"


def test_invariants_hold_on_a_realistic_plan():
    versions, children, releases = daily_releases(35)
    versions[-2].tags.append("latest")
    p = plan(versions, children, releases)
    assert gr.check_invariants(p, versions) == []


if __name__ == "__main__":
    # Runnable without pytest, so CI needs no extra dependency.
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    for name, fn in tests:
        fn()
        print(f"ok   {name}")
    print(f"{len(tests)} passed")
