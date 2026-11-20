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
