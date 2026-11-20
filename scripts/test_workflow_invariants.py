"""Invariants of publish-base-images.yml and create-release-tag.yml that GitHub
enforces only at run time, or not at all.

Read as text, without a YAML library, so CI needs no extra dependency.

Run with: python3 scripts/test_workflow_invariants.py
"""

import pathlib
import re
import sys

WORKFLOW = (pathlib.Path(__file__).resolve().parent.parent
            / ".github" / "workflows" / "publish-base-images.yml")


def jobs(text):
    """job id -> its block of text, for the top-level jobs: mapping."""
    body = text.split("\njobs:\n", 1)[1]
    found = {}
    current = None
    for line in body.splitlines():
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if match:
            current = match.group(1)
            found[current] = []
            continue
        if current is not None:
            found[current].append(line)
    return {name: "\n".join(lines) for name, lines in found.items()}


def concurrency(block):
    """The job-level concurrency: mapping as key -> value strings."""
    lines = block.splitlines()
    for index, line in enumerate(lines):
        if line == "    concurrency:":
            settings = {}
            for entry in lines[index + 1:]:
                match = re.match(r"^      ([a-z-]+):\s*(.*)$", entry)
                if not match:
                    break
                value = match.group(2).strip()
                # A quoted scalar is the same value to GitHub.
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                settings[match.group(1)] = value
            return settings
    return None


# sign-and-tag.sh modes that never touch a staging tag. Any other first
# argument (publish-index, mirror, or one chosen through a variable) may.
READ_ONLY_MODES = {"verify", "tag-digest"}


def stages_unsigned_tags(block):
    if "unsigned-staging" in block:
        return True
    # A call may be split across lines with "\" continuations.
    for mode in re.findall(r"sign-and-tag\.sh(?:\s|\\)+(\S+)", block):
        if mode.strip("\"'") not in READ_ONLY_MODES:
            return True
    return False


def test_every_job_that_stages_an_unsigned_tag_is_serialized_per_image():
    # Regression for fips-140-3 v0.0.63: two releases of one image in flight
    # shared <image>:unsigned-staging and fips-base-linux-amd64:unsigned-staging;
    # v0.0.64 repointed the staging tag 0.4 s after v0.0.63 staged it.
    text = WORKFLOW.read_text(encoding="utf-8")
    staging = {name: block for name, block in jobs(text).items()
               if stages_unsigned_tags(block)}
    assert staging, "no job calls sign-and-tag.sh publish-index or mirror"
    for name, block in staging.items():
        settings = concurrency(block)
        assert settings is not None, f"{name} stages unsigned tags with no concurrency group"
        # Exactly the image: anything more specific (a run id, the tag) puts
        # two releases of one image in different groups again.
        assert settings.get("group") == (
            "multiarch-manifests-${{ needs.create_release.outputs.image-base-name }}"
        ), (name, settings)
        assert settings.get("cancel-in-progress") == "false", (name, settings)
        # The default queue keeps one pending job and cancels older ones,
        # which would silently drop a release's tags.
        assert settings.get("queue") == "max", (name, settings)


def test_the_image_name_the_group_uses_is_an_output_of_a_job_it_needs():
    text = WORKFLOW.read_text(encoding="utf-8")
    all_jobs = jobs(text)
    for name, block in all_jobs.items():
        settings = concurrency(block) or {}
        match = re.search(r"needs\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)",
                          settings.get("group", ""))
        if not match:
            continue
        source, output = match.groups()
        assert re.search(rf"needs:.*\b{source}\b", block), (name, source)
        source_block = all_jobs[source]
        # Exactly the image name parse-image-context cut out of the tag: any
        # other value (the version, a run id appended) splits one image's
        # releases across groups again.
        bound = re.search(rf"^    outputs:\n(?:      .*\n)*      {output}: "
                          rf"\$\{{\{{ steps\.([A-Za-z0-9_-]+)\.outputs\.image-base-name \}}\}}\n",
                          source_block + "\n", re.MULTILINE)
        assert bound, (source, output)
        step = bound.group(1)
        assert re.search(rf"^        id: {step}\n        uses: \S*/\.github/actions/parse-image-context\b",
                         source_block, re.MULTILINE), (source, step)


CREATE_RELEASE_TAG = WORKFLOW.with_name("create-release-tag.yml")


def step_run_block(text, step_name):
    """The run: | script of the step with this name, dedented."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == f"- name: {step_name}":
            indent = len(line) - len(line.lstrip())
            body = None
            for follow in lines[index + 1:]:
                stripped = follow.strip()
                current = len(follow) - len(follow.lstrip())
                if body is None:
                    if stripped.startswith("- ") and current <= indent:
                        return None
                    if stripped == "run: |":
                        body, body_indent = [], None
                    continue
                if stripped and current <= indent + 2:
                    break
                if body_indent is None and stripped:
                    body_indent = current
                body.append(follow[body_indent:] if stripped else "")
            return "\n".join(body) + "\n" if body is not None else None
    return None


def run_next_version(script, current):
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        output = pathlib.Path(tmp) / "out"
        output.write_text("")
        done = subprocess.run(["/bin/bash", "-e", "-c", script],
                              env={"CURRENT": current, "GITHUB_OUTPUT": str(output),
                                   "PATH": "/usr/bin:/bin"},
                              capture_output=True, text=True, timeout=30)
        values = dict(line.split("=", 1) for line in output.read_text().splitlines() if "=" in line)
        return done.returncode, values, done.stdout + done.stderr


def step_block(text, step_name):
    """The text of the step with this name, up to the next step."""
    match = re.search(rf"^( +)- name: {re.escape(step_name)}\n(.*?)(?=^\1- |\Z)",
                      text, re.MULTILINE | re.DOTALL)
    return match.group(2) if match else None


def test_next_version_is_computed_in_the_workflow_not_by_a_docker_action():
    # The step used a Docker action whose image tag could change under its
    # pinned commit, and its output became the release tag pushed with the
    # deploy key.
    text = CREATE_RELEASE_TAG.read_text(encoding="utf-8")
    assert "github-action-next-semvers" not in text
    assert "docker://" not in text, "a docker:// action is back in create-release-tag.yml"
    step = step_block(text, "Calculate next version")
    assert step, "no Calculate next version step"
    # The step the push reads is this one, runs bash (the default; [[ ]]
    # needs it) and reads the version the latest-tag step wrote.
    assert re.search(r"^ +id: next_version$", step, re.MULTILINE), step
    assert "uses:" not in step, step
    # No shell override anywhere: a job or workflow default of sh would run
    # this bash script under another shell.
    assert "shell:" not in text, "a shell: setting is in create-release-tag.yml"
    # It always runs and its failure stops the job: skipped or allowed to
    # fail, it would leave the push step an empty version.
    assert "continue-on-error" not in step and not re.search(r"^ +if:", step, re.MULTILINE), step
    assert re.search(r"^ +CURRENT: \$\{\{ steps\.latest_tag\.outputs\.current_semver \}\}$",
                     step, re.MULTILINE), step
    latest = step_block(text, "Find latest tag for image")
    assert latest and re.search(r"^ +id: latest_tag$", latest, re.MULTILINE), latest
    assert 'echo "current_semver=$semver" >> "$GITHUB_OUTPUT"' in latest
    push = step_block(text, "Create and push release tag")
    assert push and re.search(r"^ +NEXT_PATCH: \$\{\{ steps\.next_version\.outputs\.patch \}\}$",
                              push, re.MULTILINE), push
    script = step_run_block(text, "Calculate next version")
    assert script, "the Calculate next version step has no run: | block"
    for current, expected in (("1.1.564", ("1.1.565", "1.2.0", "2.0.0")),
                              ("0.0.0", ("0.0.1", "0.1.0", "1.0.0")),
                              ("2.9.9", ("2.9.10", "2.10.0", "3.0.0")),
                              ("1.08.09", ("1.8.10", "1.9.0", "2.0.0")),
                              ("08.1.1", ("8.1.2", "8.2.0", "9.0.0")),
                              ("999999999.0.0", ("999999999.0.1", "999999999.1.0", "1000000000.0.0"))):
        rc, values, out = run_next_version(script, current)
        assert rc == 0, (current, out)
        assert (values.get("patch"), values.get("minor"), values.get("major")) == expected, (
            current, values)


def test_a_malformed_current_version_never_becomes_a_tag():
    script = step_run_block(CREATE_RELEASE_TAG.read_text(encoding="utf-8"),
                            "Calculate next version")
    assert script
    # Parts too long for shell arithmetic would wrap into a negative or
    # unrelated number instead of failing.
    # Each part is bounded and non-empty: bash 5 reads an empty part as an
    # error it does not stop on, and would print "patch=1..3".
    for bad in ("", "1.2", "1.2.3-rc1", "v1.2.3", "1.2.3\npatch=9.9.9", "1.2.x",
                "1.2.9223372036854775807", "1.2.99999999999999999999", "1234567890.0.0",
                "1.99999999999999999999.0", "1.1234567890.0", "1..2", "1.2.", ".1.2"):
        rc, values, out = run_next_version(script, bad)
        assert rc != 0 and "patch" not in values, (bad, values, out)


# A shell function shadows the git command, so the push script runs unchanged
# and every git call is recorded instead of executed.
GIT_STUB = """git() {
  echo "$*" >> "$GIT_LOG"
  if [ "$1 $2" = "remote get-url" ]; then
    echo "${STUB_ORIGIN:-git@github.com:aquia-inc/base-docker-images.git}"
  fi
  if [ "$1" = "push" ] && [ -n "${STUB_PUSH_FAILS:-}" ]; then
    return 1
  fi
}
"""


def run_push(script, next_patch, **stub):
    """Run the push step's script with git stubbed; returns the exit code, the
    git calls and the output. It runs in an empty directory with an empty PATH
    and GIT_DIR naming a directory that does not exist, so a script that got
    past the stub (command git, /usr/bin/git) fails instead of tagging any
    repository. stub: STUB_ORIGIN, STUB_PUSH_FAILS."""
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp) / "work"
        empty = pathlib.Path(tmp) / "no-commands"
        work.mkdir()
        empty.mkdir()
        log = pathlib.Path(tmp) / "git.log"
        log.write_text("")
        done = subprocess.run(["/bin/bash", "-e", "-c", GIT_STUB + script], cwd=work,
                              env={"IMAGE_NAME": "python-base", "NEXT_PATCH": next_patch,
                                   "GIT_LOG": str(log), "PATH": str(empty),
                                   "GIT_DIR": str(pathlib.Path(tmp) / "no-repository"),
                                   "GITHUB_ACTIONS": "true", **stub},
                              capture_output=True, text=True, timeout=30)
        return done.returncode, log.read_text().splitlines(), done.stdout + done.stderr


def test_the_push_step_tags_only_a_plain_next_version():
    text = CREATE_RELEASE_TAG.read_text(encoding="utf-8")
    push = step_block(text, "Create and push release tag")
    assert push, "no Create and push release tag step"
    # It runs only on main, and only when every step before it succeeded.
    assert re.search(r"^ +if: github\.event\.ref == 'refs/heads/main'$", push, re.MULTILINE), push
    assert "continue-on-error" not in push, push
    # Its only inputs are the image and the version step's output, and the
    # tag is built from exactly those two.
    assert re.search(r"^ +env:\n +IMAGE_NAME: \$\{\{ matrix\.image_name \}\}\n"
                     r" +NEXT_PATCH: \$\{\{ steps\.next_version\.outputs\.patch \}\}\n +run: \|$",
                     push, re.MULTILINE), push
    script = step_run_block(text, "Create and push release tag")
    assert script, "the push step has no run: | block"
    assert 'new_tag="release/${IMAGE_NAME}/v${NEXT_PATCH}"' in script, script
    assert not re.search(r"\b(IMAGE_NAME|NEXT_PATCH|new_tag)=", script.replace(
        'new_tag="release/${IMAGE_NAME}/v${NEXT_PATCH}"', "")), script
    rc, calls, out = run_push(script, "1.1.567")
    assert rc == 0, out
    # Exactly these git calls, so nothing else is tagged or pushed.
    assert calls == [
        "remote get-url origin",
        "config user.email aquia-base-images-bot@users.noreply.github.com",
        "config user.name Aquia Base Images Bot",
        "tag -a release/python-base/v1.1.567 -m Release python-base/v1.1.567",
        "push origin release/python-base/v1.1.567",
    ], calls
    # Without the deploy key's ssh remote nothing is tagged, and a failed
    # push fails the step.
    rc, calls, out = run_push(script, "1.1.567", STUB_ORIGIN="https://github.com/aquia-inc/x.git")
    assert rc != 0 and not [c for c in calls if c.startswith(("tag", "push"))], (calls, out)
    rc, calls, out = run_push(script, "1.1.567", STUB_PUSH_FAILS="1")
    assert rc != 0, (calls, out)
    # Whatever reaches it - an empty output from a skipped version step, or
    # anything that is not X.Y.Z - no tag is created.
    for bad in ("", "1.2", "v1.2.3", "1..3", "1.2.3 x", "1.2.3\n", "1.2.3-rc1",
                "12345678901.0.0", "1.12345678901.0", "1.0.12345678901", "1x2x3"):
        rc, calls, out = run_push(script, bad)
        assert rc != 0, (bad, out)
        assert not [c for c in calls if c.startswith(("tag", "push"))], (bad, calls)


# ---------------------------------------------------------------------------
# Pull requests build every image whose release inputs they change
# ---------------------------------------------------------------------------

# The checks branch protection requires on main, by exact name.
REQUIRED_BUILD_CHECKS = ("publish_image (linux/amd64)", "publish_image (linux/arm64)")


# Stand-ins for git and python3 in the select step, so its own logic runs:
# what it reads, what it refuses and what it writes to GITHUB_OUTPUT.
SELECT_STUBS = """git() {
  echo "git $*" >> "$CALLS"
  case "$*" in
    "rev-parse --verify --quiet HEAD^2") [ "${STUB_MERGE:-1}" = 1 ] ;;
    "rev-parse HEAD^1") echo "${STUB_PARENT}" ;;
    *) return 99 ;;
  esac
}
python3() {
  echo "python3 $*" >> "$CALLS"
  case "$3" in
    since) printf '%s\\n' "${STUB_SINCE}"; return "${STUB_SINCE_RC:-0}" ;;
    red) printf '%s\\n' "${STUB_RED}"; return "${STUB_RED_RC:-0}" ;;
    *) return 99 ;;
  esac
}
"""
PARENT = "a" * 40


def run_select(script, event="pull_request", **stub):
    import shutil
    import subprocess
    import tempfile
    jq_dir = str(pathlib.Path(shutil.which("jq")).parent)
    with tempfile.TemporaryDirectory() as tmp:
        out, calls = pathlib.Path(tmp) / "out", pathlib.Path(tmp) / "calls"
        out.write_text("")
        calls.write_text("")
        env = {"EVENT_NAME": event, "REPO": "o/r", "GITHUB_OUTPUT": str(out), "CALLS": str(calls),
               "PATH": f"/usr/bin:/bin:{jq_dir}", "STUB_PARENT": PARENT, **stub}
        done = subprocess.run(["/bin/bash", "-e", "-c", SELECT_STUBS + script], env=env,
                              capture_output=True, text=True, timeout=30)
        values = dict(line.split("=", 1) for line in out.read_text().splitlines() if "=" in line)
        return done.returncode, values, calls.read_text().splitlines(), done.stdout + done.stderr


def test_a_pull_request_builds_every_image_whose_release_inputs_it_changes():
    # Building only the first changed Dockerfile let #844, which changed all
    # eight, merge with one image built; a change to a shared input built none.
    text = WORKFLOW.read_text(encoding="utf-8")
    found = jobs(text)
    select = found.get("select_images")
    assert select is not None, "no select_images job: a pull request must select its images"
    # The payload's base commit can be older than the commit GitHub merged the
    # pull request into (measured: 2 of 7 runs); the merge's first parent is not.
    assert "base.sha" not in select and "BASE_SHA" not in select
    assert "      images: ${{ steps.select.outputs.images }}" in select
    assert "      known_red: ${{ steps.select.outputs.known_red }}" in select
    assert "      actions: read" in select and "continue-on-error" not in select
    tests = step_block(text, "Selector and gate tests")
    assert tests is not None and "python3 -B scripts/test_release_inputs.py" in tests
    assert "python3 -B scripts/test_pr_gate.py" in tests
    assert select.index("- name: Selector and gate tests") < select.index("- name: Select images")
    publish = found["publish_image"]
    assert re.search(r"^    needs: select_images$", publish, re.MULTILINE), "publish_image"
    assert "        image: ${{ fromJSON(needs.select_images.outputs.images) }}" in publish
    # The first-changed-Dockerfile pick is gone.
    assert "head -n 1" not in publish and "^Dockerfile" not in publish
    detect = step_run_block(text, "Detect image for PR builds")
    assert detect is not None and "PR_IMAGE" in detect, detect


def test_the_selection_diffs_against_the_merge_parent_and_checks_what_it_writes():
    script = step_run_block(WORKFLOW.read_text(encoding="utf-8"), "Select images")
    assert script is not None
    rc, out, calls, log = run_select(script, STUB_SINCE='["nginx-base", "python-base"]',
                                     STUB_RED='["python-base"]')
    assert rc == 0, log
    assert out == {"images": '["nginx-base","python-base"]', "known_red": '["python-base"]'}, out
    assert f"python3 -B scripts/release-inputs.py since {PARENT}" in calls, calls
    # Nothing changed: one reporting leg per platform, so the matrix is never empty.
    rc, out, _, log = run_select(script, STUB_SINCE="[]", STUB_RED="[]")
    assert rc == 0 and out == {"images": '[""]', "known_red": "[]"}, (out, log)
    # Not a merge commit: refuse rather than diff against the wrong commit.
    rc, out, _, _ = run_select(script, STUB_MERGE="0", STUB_SINCE='["a"]', STUB_RED="[]")
    assert rc != 0 and out == {}, out
    # The selector failing, or printing anything but a list of plain names, fails
    # the step before anything reaches GITHUB_OUTPUT.
    for since_out, since_rc in (('["a"]', 1), ('["a"]\nevil=1', 0), ("hello", 0), ('["A"]', 0),
                                ("[1]", 0), ('["a", ""]', 0), ('["../x"]', 0), ("", 0),
                                ('["a"] ["b"]', 0), ('["a\\n"]', 0), ('["a.."]', 0)):
        rc, out, _, _ = run_select(script, STUB_SINCE=since_out, STUB_SINCE_RC=str(since_rc),
                                   STUB_RED="[]")
        assert rc != 0 and out == {}, (since_out, out)
    # The publish results unreadable: exempt nothing, and say so.
    rc, out, _, log = run_select(script, STUB_SINCE='["a"]', STUB_RED="", STUB_RED_RC="1")
    assert rc == 0 and out == {"images": '["a"]', "known_red": "[]"}, out
    assert "::warning::" in log, log
    # A malformed list of red images is never trusted to exempt anything.
    rc, out, _, _ = run_select(script, STUB_SINCE='["a"]', STUB_RED='["a"]\nx=1')
    assert rc != 0 and out == {}, out
    # Outside a pull request nothing is read: the image comes from the tag.
    rc, out, calls, _ = run_select(script, event="push")
    assert rc == 0 and out == {"images": '[""]', "known_red": "[]"} and calls == [], (out, calls)


def test_an_image_name_from_a_pull_request_is_checked_before_it_is_used():
    # The image list comes from file names in the pull request, and the name is
    # written to GITHUB_ENV: anything but a plain name must stop the leg.
    script = step_run_block(WORKFLOW.read_text(encoding="utf-8"), "Detect image for PR builds")
    import subprocess
    import tempfile
    for name, ok in (("python-base", True), ("go-base-1.27", True), ("", True),
                     ("a\nTAG=x", False), ("../x", False), ("A", False), ("a b", False),
                     ("-x", False), ("a/b", False), ("a$(id)", False)):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = pathlib.Path(tmp) / "env"
            out_file = pathlib.Path(tmp) / "out"
            env_file.write_text("")
            out_file.write_text("")
            done = subprocess.run(["/bin/bash", "-e", "-c", script],
                                  env={"PR_IMAGE": name, "GITHUB_ENV": str(env_file),
                                       "GITHUB_OUTPUT": str(out_file), "PATH": "/usr/bin:/bin"},
                                  capture_output=True, text=True, timeout=30)
            assert (done.returncode == 0) == ok, (name, done.stdout, done.stderr)
            if not ok:
                assert env_file.read_text() == "", (name, env_file.read_text())
            elif name:
                assert env_file.read_text() == f"TAG=release/{name}/v0.0.0-pr\n"
                assert out_file.read_text() == "dockerfile_found=true\n"
            else:
                assert env_file.read_text() == ""
                assert out_file.read_text() == "dockerfile_found=false\n"


GATE_STUBS = """gh() { echo "gh $*" >> "$CALLS"; echo '{"total_count": 0, "jobs": []}'; return "${STUB_GH_RC:-0}"; }
python3() { echo "python3 $*" >> "$CALLS"; return "${STUB_GATE_RC:-0}"; }
"""


def run_gate(script, select_result, **stub):
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        calls = pathlib.Path(tmp) / "calls"
        calls.write_text("")
        env = {"SELECT_RESULT": select_result, "IMAGES": '["a"]', "KNOWN_RED": "[]",
               "PLATFORM": "linux/amd64", "REPO": "o/r", "RUN_ID": "7", "CALLS": str(calls),
               "PATH": "/usr/bin:/bin", **stub}
        done = subprocess.run(["/bin/bash", "-e", "-c", GATE_STUBS + script], env=env, cwd=tmp,
                              capture_output=True, text=True, timeout=30)
        return done.returncode, calls.read_text().splitlines()


def test_the_required_checks_come_only_from_the_gate():
    text = WORKFLOW.read_text(encoding="utf-8")
    found = jobs(text)
    named = [job for job, block in found.items()
             if "    name: publish_image (${{ matrix.platform }})" in block.splitlines()]
    assert named == ["pr_gate"], f"exactly one job carries the required names: {named}"
    gate = found["pr_gate"]
    assert "    needs: [select_images, publish_image]" in gate
    assert "    if: ${{ always() && github.event_name == 'pull_request' }}" in gate
    assert "        platform: [linux/amd64, linux/arm64]" in gate
    # One platform's failure must not cancel the other's verdict.
    assert "      fail-fast: false" in gate
    assert "      actions: read" in gate and "continue-on-error" not in gate
    # Pull request legs are named per image and dispatch legs say so: only a
    # release tag's legs carry the plain names, and no pull request has those.
    assert ("    name: ${{ github.event_name == 'pull_request' && format('publish_image ({0}, "
            "{1})', matrix.image || 'no image changed', matrix.platform) || "
            "(github.event_name == 'push' && github.ref_type == 'tag') && "
            "format('publish_image ({0})', matrix.platform) || "
            "format('publish_image (dispatch, {0})', matrix.platform) }}") in found["publish_image"]
    script = step_run_block(text, "Every build leg passed")
    assert script is not None
    assert ('gh api "repos/${REPO}/actions/runs/${RUN_ID}/jobs?filter=latest&per_page=100"'
            ' > jobs.json') in script
    assert 'python3 -B scripts/pr-gate.py jobs.json "$PLATFORM" "$IMAGES" "$KNOWN_RED"' in script
    for select in ("failure", "cancelled", "skipped", ""):
        rc, calls = run_gate(script, select)
        assert rc != 0 and calls == [], (select, calls)
    rc, calls = run_gate(script, "success")
    assert rc == 0 and [c.split()[0] for c in calls] == ["gh", "python3"], calls
    assert run_gate(script, "success", STUB_GH_RC="1")[0] != 0
    assert run_gate(script, "success", STUB_GATE_RC="1")[0] != 0
    for check in REQUIRED_BUILD_CHECKS:
        platform = check.split("(", 1)[1].rstrip(")")
        assert platform in gate, check


def test_renovate_is_approved_only_when_the_gate_passed():
    approve = jobs(WORKFLOW.read_text(encoding="utf-8"))["auto_approve_renovate"]
    assert "    needs: [pr_gate]" in approve
    assert ("    if: ${{ always() && github.event_name == 'pull_request' && "
            "github.event.pull_request.user.login == 'renovate[bot]' && "
            "needs.pr_gate.result == 'success' }}") in approve


def test_no_cache_export_can_fail_a_release():
    # The Actions cache sits at its size cap; a cache write error must not fail
    # a release leg (the test builds run on release tags too).
    publish = jobs(WORKFLOW.read_text(encoding="utf-8"))["publish_image"]
    exports = [line for line in publish.splitlines() if line.strip().startswith("cache-to:")]
    assert len(exports) == 3, exports
    for line in exports:
        assert line.endswith(",ignore-error=true"), line


if __name__ == "__main__":
    import traceback
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    failed = []
    for name, fn in tests:
        try:
            fn()
        # SystemExit counts as a failure (an exit inside a test must not end
        # the run as if it passed); Ctrl-C still stops the run.
        except (Exception, SystemExit):
            failed.append(name)
            print(f"FAIL {name}")
            traceback.print_exc()
        else:
            print(f"ok   {name}")
    print(f"{len(tests) - len(failed)} passed, {len(failed)} failed")
    if failed:
        sys.exit(1)
