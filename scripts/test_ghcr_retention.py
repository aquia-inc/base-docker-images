"""Unit tests for the planning logic in ghcr-retention.py (no network)."""

import datetime as dt
import http.client
import importlib.util
import io
import pathlib
import sys
import urllib.error

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


def test_registered_secret_is_scrubbed_from_error_text():
    secret = "ghp_" + "a" * 36
    gr.remember_secret(secret)
    leaked = f'{{"message":"bad credentials for {secret}"}}'
    assert secret not in gr.redact(leaked)
    assert "<redacted>" in gr.redact(leaked)


def test_base64_form_of_a_secret_is_also_scrubbed():
    # The registry takes HTTP Basic, so the credential travels base64-encoded.
    # Scrubbing only the raw value would leave a trivially decodable copy.
    import base64 as b64

    secret = "ghp_" + "b" * 36
    gr.remember_secret(secret)
    encoded = b64.b64encode(f"x:{secret}".encode()).decode()
    assert secret not in gr.redact(f"Authorization: Basic {encoded}")


def test_short_values_are_not_registered_as_secrets():
    # Guards against a degenerate value turning redact() into a text mangler
    # that corrupts every message it touches.
    gr.remember_secret("abc")
    assert gr.redact("abc def") == "abc def"


def _tree():
    import ast

    return ast.parse(pathlib.Path(__file__).with_name("ghcr-retention.py").read_text())


def _enclosing_functions(tree):
    """Map every node to the name of the top-level function that contains it."""
    import ast

    owner = {}
    for fn in tree.body:
        if isinstance(fn, ast.FunctionDef):
            for node in ast.walk(fn):
                owner[node] = fn.name
    return owner


def test_the_only_delete_request_is_in_delete_version():
    """Deletion is deliberate and confined to one function. Enforce it.

    This replaces the report-only era's test that no DELETE existed at all:
    adding the delete path was an explicit owner decision (README "Image
    Retention", effective 2026-10-26). What stays enforced is that there is
    exactly one place a DELETE can be issued, so every guard in front of it
    can be reasoned about. Checked structurally, as before: urllib can only
    issue a DELETE via Request(method=...) or a get_method override.
    """
    import ast

    tree = _tree()
    owner = _enclosing_functions(tree)
    sites = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            assert node.name != "get_method", "get_method override found"
        if isinstance(node, ast.keyword) and node.arg == "method":
            if str(getattr(node.value, "value", "")).upper() == "DELETE":
                sites.append(owner.get(node))
            else:
                assert isinstance(node.value, ast.Constant), "a computed HTTP method"
    assert sites == ["delete_version"], sites


def test_delete_version_is_reached_only_from_main_after_the_guards():
    """delete_version is called from main alone, after apply_refusals."""
    import ast

    tree = _tree()
    owner = _enclosing_functions(tree)
    callers = [owner.get(node) for node in ast.walk(tree)
               if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "delete_version"]
    assert callers == ["main"], callers
    main = next(fn for fn in tree.body if isinstance(fn, ast.FunctionDef) and fn.name == "main")
    lines = {getattr(n.func, "id", ""): n.lineno for n in ast.walk(main) if isinstance(n, ast.Call)}
    assert lines["apply_refusals"] < lines["delete_version"]


# ---------------------------------------------------------------------------
# Deletion guards and ordering
# ---------------------------------------------------------------------------

def test_apply_is_refused_before_the_announced_date():
    day_before = gr.EFFECTIVE_DATE - dt.timedelta(days=1)
    assert any("before the announced date" in r for r in gr.apply_refusals(day_before, [], 10, 100))
    assert gr.apply_refusals(gr.EFFECTIVE_DATE, [], 10, 100) == []


def test_apply_is_refused_when_an_invariant_fails():
    assert gr.apply_refusals(gr.EFFECTIVE_DATE, ["x"], 10, 100)


def test_apply_is_refused_without_a_positive_expectation():
    assert gr.apply_refusals(gr.EFFECTIVE_DATE, [], 10, 0)
    assert gr.apply_refusals(gr.EFFECTIVE_DATE, [], 10, -5)


def test_apply_is_refused_when_the_plan_exceeds_the_expectation():
    refusals = gr.apply_refusals(gr.EFFECTIVE_DATE, [], 101, 100)
    assert refusals and "more than --expect-at-most" in refusals[0]
    assert gr.apply_refusals(gr.EFFECTIVE_DATE, [], 100, 100) == []


def test_invariant_requires_the_release_floor():
    versions, children, releases = daily_releases(35)
    p = plan(versions, children, releases)
    assert gr.check_invariants(p, versions, releases, 30) == []
    # A planner fault that deletes a kept release must be caught independently.
    victim = next(v for v in versions if v.tags and v.digest in p.keep)
    p.keep.pop(victim.digest)
    p.delete[victim.digest] = "fault"
    assert any("fewer than 30" in x for x in gr.check_invariants(p, versions, releases, 30))


def test_invariant_floor_is_the_release_count_when_there_are_fewer():
    versions, children, releases = daily_releases(3)
    p = plan(versions, children, releases)
    assert gr.check_invariants(p, versions, releases, 30) == []


def groups_for(versions, children, releases):
    p = plan(versions, children, releases)
    return p, gr.deletion_groups(p, versions, children, releases)


def test_each_release_is_one_group_children_first_release_last():
    versions, children, releases = daily_releases(35)
    p, groups = groups_for(versions, children, releases)
    assert len(groups) == 5
    for g in groups:
        assert g.order[-1] == g.anchor and not g.held
        assert g.order[:-1] == children[g.anchor]
    covered = [d_ for g in groups for d_ in g.order]
    assert sorted(covered) == sorted(p.delete) and len(covered) == len(set(covered))


def test_groups_go_oldest_release_first():
    versions, children, releases = daily_releases(35)
    _, groups = groups_for(versions, children, releases)
    by_digest = {v.digest: v for v in versions}
    created = [by_digest[g.anchor].created for g in groups]
    assert created == sorted(created)


def test_signatures_join_their_subjects_group_before_the_release():
    versions, children, releases = daily_releases(35)
    gone_hex = versions[-2].digest.split(":")[1]
    versions += [version(9201, 200, [f"sha256-{gone_hex}"]), version(9202, 200, [])]
    children[d(9201)] = [d(9202)]
    _, groups = groups_for(versions, children, releases)
    group = next(g for g in groups if g.anchor == versions[-4].digest)
    assert group.order == [d(9202), d(9201), *children[versions[-4].digest], versions[-4].digest]


def test_signature_of_an_absent_subject_is_its_own_group():
    versions, children, releases = daily_releases(3, start_days_old=1)
    versions.append(version(9301, 200, ["sha256-" + "e" * 64 + ".sig"]))
    _, groups = groups_for(versions, children, releases)
    assert [g.anchor for g in groups] == [d(9301)]


def test_a_release_with_a_stale_tracking_tag_waits_for_retirement():
    versions, children, releases = daily_releases(35)
    versions[-2].tags.append("3.13.11")
    _, groups = groups_for(versions, children, releases)
    held = [g for g in groups if g.held]
    assert len(held) == 1 and held[0].anchor == versions[-2].digest
    assert held[0].held == ["3.13.11"]


class Deleter:
    """Scripted delete_version: one (status, headers, detail) per call."""

    def __init__(self, outcomes=None, default=(204, {}, "")):
        self.outcomes, self.default, self.calls = list(outcomes or []), default, []

    def __call__(self, version_id):
        self.calls.append(version_id)
        return self.outcomes.pop(0) if self.outcomes else self.default


def execute(versions, children, releases, deleter, budget=1000, current=None):
    p, groups = groups_for(versions, children, releases)
    planned_tags = {v.digest: list(v.tags) for v in versions}
    if current is None:
        current = {v.digest: (v.id, list(v.tags)) for v in versions}
    outcome, sleeps = gr.Outcome(), []
    gr.run_deletions("python-base", groups, planned_tags, current, deleter, budget, outcome,
                     sleep=sleeps.append, now=lambda: 1000.0)
    return outcome, sleeps


def test_deletions_run_children_first_and_are_paced():
    versions, children, releases = daily_releases(35)
    outcome, sleeps = execute(versions, children, releases, deleter := Deleter())
    assert outcome.attempted == 10 and not outcome.stopped
    assert deleter.calls[:2] == [5034, 1034]           # oldest release: child, then index
    assert sleeps == [gr.DELETE_SPACING_SECONDS] * 9
    assert {e["result"] for e in outcome.log} == {"deleted"}


def test_budget_is_spent_in_whole_groups():
    versions, children, releases = daily_releases(35)
    outcome, _ = execute(versions, children, releases, Deleter(), budget=3)
    assert outcome.attempted == 4                      # the second group is finished


def test_a_held_group_is_never_touched():
    versions, children, releases = daily_releases(35)
    versions[-2].tags.append("3.13.11")
    outcome, _ = execute(versions, children, releases, deleter := Deleter())
    assert versions[-2].id not in deleter.calls and outcome.attempted == 8


def test_a_group_whose_tags_changed_since_the_plan_is_skipped():
    versions, children, releases = daily_releases(35)
    current = {v.digest: (v.id, list(v.tags)) for v in versions}
    current[versions[-2].digest] = (versions[-2].id, versions[-2].tags + ["latest"])
    outcome, _ = execute(versions, children, releases, deleter := Deleter(), current=current)
    assert versions[-2].id not in deleter.calls
    assert any(e["result"] == "skipped" for e in outcome.log)


def test_a_version_already_gone_is_not_requested():
    versions, children, releases = daily_releases(35)
    current = {v.digest: (v.id, list(v.tags)) for v in versions if v.id != 5034}
    outcome, _ = execute(versions, children, releases, deleter := Deleter(), current=current)
    assert 5034 not in deleter.calls and outcome.attempted == 9


def test_404_counts_as_already_gone():
    versions, children, releases = daily_releases(31)
    outcome, _ = execute(versions, children, releases, Deleter([(404, {}, "")]))
    assert [e["result"] for e in outcome.log] == ["already gone", "deleted"]


def test_a_refusal_leaves_the_rest_of_its_group_and_the_run_continues():
    versions, children, releases = daily_releases(32)
    refusal = (400, {}, "more than 5000 downloads")
    outcome, _ = execute(versions, children, releases, deleter := Deleter([refusal]))
    assert outcome.log[0]["result"] == "refused" and "5000" in outcome.log[0]["detail"]
    # The child could not go, so its index (the tagged release) is kept for a
    # later run rather than deleted over it; the next group proceeds.
    assert 1031 not in deleter.calls and deleter.calls == [5031, 5030, 1030]
    assert not outcome.stopped


def test_a_transient_error_is_retried_before_it_counts():
    versions, children, releases = daily_releases(31)
    outcome, sleeps = execute(versions, children, releases,
                              Deleter([(502, {}, "bad gateway"), (0, {}, "RemoteDisconnected")]))
    assert [e["result"] for e in outcome.log] == ["deleted", "deleted"]
    assert sleeps[:4] == [2.0, gr.DELETE_SPACING_SECONDS, 4.0, gr.DELETE_SPACING_SECONDS]


def test_consecutive_failures_stop_the_run():
    versions, children, releases = daily_releases(35)
    outcome, _ = execute(versions, children, releases,
                         Deleter(default=(403, {}, "admin access required")))
    assert outcome.failed and outcome.attempted == gr.MAX_CONSECUTIVE
    assert "admin access required" in outcome.stopped


def test_a_rate_limited_request_waits_then_retries():
    versions, children, releases = daily_releases(31)
    limited = (429, {"Retry-After": "30"}, "slow down")
    outcome, sleeps = execute(versions, children, releases, Deleter([limited]))
    assert 30.0 in sleeps and [e["result"] for e in outcome.log] == ["deleted", "deleted"]


def test_an_exhausted_rate_limit_waits_until_reset():
    headers = {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1060"}
    assert gr.rate_limit_wait(403, headers, 1000.0) == 60.0
    assert gr.rate_limit_wait(403, {}, 1000.0) is None
    assert gr.rate_limit_wait(204, headers, 1000.0) is None
    assert gr.rate_limit_wait(429, {"retry-after": "99999"}, 0.0) == gr.MAX_RATE_WAIT_SECONDS


def test_the_run_stops_at_the_rate_budget_floor():
    versions, children, releases = daily_releases(35)
    low = (204, {"x-ratelimit-remaining": str(gr.RATE_FLOOR)}, "")
    outcome, _ = execute(versions, children, releases, Deleter([low]))
    assert outcome.attempted == 1 and "rate budget" in outcome.stopped and not outcome.failed


def test_retirements_merge_the_three_packages_of_an_image():
    plans = [gr.Plan(package="nodejs-base", image="nodejs-base", retire={"24.10": d(1)}),
             gr.Plan(package="nodejs-base-linux-amd64", image="nodejs-base", retire={"24.10": d(2)}),
             gr.Plan(package="nodejs-base-linux-arm64", image="nodejs-base", retire={"24.10": d(3)}),
             gr.Plan(package="go-base-linux-arm64", image="go-base", retire={"1.25": d(4)})]
    assert gr.retirements(plans) == [
        {"image": "go-base", "tag": "1.25", "digest": "-", "amd64": "-", "arm64": d(4)},
        {"image": "nodejs-base", "tag": "24.10", "digest": d(1), "amd64": d(2), "arm64": d(3)}]


def test_retirements_never_name_an_always_kept_tag():
    plans = [gr.Plan(package="fips-base", image="fips-base", retire={"openssl3": d(1), "latest": d(2)})]
    assert gr.retirements(plans) == []


def test_the_retire_list_is_written_only_after_the_guards():
    import ast

    main = next(fn for fn in _tree().body if isinstance(fn, ast.FunctionDef) and fn.name == "main")
    lines = {getattr(n.func, "id", ""): n.lineno for n in ast.walk(main) if isinstance(n, ast.Call)}
    assert lines["apply_refusals"] < lines["retirements"]


def test_delete_version_reports_errors_without_raising_or_leaking():
    secret = "ghp_" + "c" * 36
    gr.remember_secret(secret)
    saved = gr._OPENER
    gr._OPENER = _Opener([urllib.error.HTTPError(
        "https://api.github.com/x", 403, "Forbidden", {},
        io.BytesIO(f'{{"message":"no admin for {secret}"}}'.encode()))])
    try:
        status, _, detail = gr.delete_version("o", "r", "p", 12, secret)
    finally:
        gr._OPENER = saved
    assert status == 403 and secret not in detail and "<redacted>" in detail


def test_invariants_hold_on_a_realistic_plan():
    versions, children, releases = daily_releases(35)
    versions[-2].tags.append("latest")
    p = plan(versions, children, releases)
    assert gr.check_invariants(p, versions) == []



class _Response:
    def __init__(self, body: bytes):
        self._body = io.BytesIO(body)
        self.headers = {"Link": ""}

    def read(self, *args):
        return self._body.read(*args)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Opener:
    """Replays a scripted sequence: an exception to raise, or a body to return."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def open(self, request, timeout=None):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return _Response(outcome)


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://api.github.com/x", code, "err", {},
                                  io.BytesIO(b"{}"))


def with_opener(outcomes):
    """Run http_json against scripted outcomes; return (result or error, calls, sleeps)."""
    opener, sleeps = _Opener(outcomes), []
    saved = gr._OPENER, gr._sleep
    gr._OPENER, gr._sleep = opener, sleeps.append
    try:
        try:
            result = gr.http_json("https://api.github.com/x", {})
        except Exception as error:  # noqa: BLE001 - the error is the result
            result = error
    finally:
        gr._OPENER, gr._sleep = saved
    return result, opener.calls, sleeps


def test_dropped_connection_is_retried_then_succeeds():
    result, calls, sleeps = with_opener([
        http.client.RemoteDisconnected("closed"),
        http.client.RemoteDisconnected("closed"),
        b'[{"id": 1}]'])
    assert result[0] == [{"id": 1}]
    assert calls == 3 and sleeps == [2, 4]


def test_server_error_is_retried():
    result, calls, sleeps = with_opener([_http_error(503), b"[]"])
    assert result[0] == [] and calls == 2 and sleeps == [2]


def test_client_error_is_raised_at_once_and_never_retried():
    result, calls, sleeps = with_opener([_http_error(404), b"[]"])
    assert isinstance(result, urllib.error.HTTPError) and result.code == 404
    assert calls == 1 and sleeps == []


def test_persistent_failure_is_raised_after_bounded_attempts():
    result, calls, sleeps = with_opener(
        [http.client.RemoteDisconnected("closed")] * (gr.RETRIES + 1))
    assert isinstance(result, http.client.RemoteDisconnected)
    assert calls == gr.RETRIES + 1 and sleeps == [2, 4, 8]


def test_persistent_server_error_keeps_its_status():
    result, calls, _ = with_opener([_http_error(502)] * (gr.RETRIES + 1))
    assert isinstance(result, urllib.error.HTTPError) and result.code == 502
    assert calls == gr.RETRIES + 1

if __name__ == "__main__":
    # Runnable without pytest, so CI needs no extra dependency.
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    for name, fn in tests:
        fn()
        print(f"ok   {name}")
    print(f"{len(tests)} passed")
