"""Unit tests for release-inputs.py: Dockerfile parsing and change detection.

The change-detection tests build a throwaway git repository in a temporary
directory, so they need git but no network, Docker or registry.
"""

import importlib.util
import io
import pathlib
import subprocess
import sys
import tempfile

_spec = importlib.util.spec_from_file_location(
    "release_inputs", pathlib.Path(__file__).with_name("release-inputs.py"))
ri = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ri
_spec.loader.exec_module(ri)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def test_plain_copy_and_add_sources_are_found():
    text = "FROM x\nCOPY a.txt /a\nADD b.tar.gz /b\n"
    assert ri.copy_sources(text) == ["a.txt", "b.tar.gz"]


def test_flags_are_not_mistaken_for_sources():
    text = "COPY --chown=nonroot:nonroot --chmod=0755 --link scripts/x.py /tmp/x.py\n"
    assert ri.copy_sources(text) == ["scripts/x.py"]


def test_copy_from_another_stage_is_not_a_build_input():
    text = "COPY --from=builder /out/app /app\nCOPY --from=ghcr.io/x/y:1 /bin/z /z\n"
    assert ri.copy_sources(text) == []


def test_several_sources_and_json_form():
    text = 'COPY a b c/ /dst/\nCOPY ["with space.txt", "d.txt", "/dst/"]\n'
    assert ri.copy_sources(text) == ["a", "b", "c", "with space.txt", "d.txt"]


def test_continuations_comments_and_blank_lines_are_joined_like_docker():
    text = "COPY \\\n  # a comment inside the continuation\n\n  one.txt \\\n  /dst\n"
    assert ri.copy_sources(text) == ["one.txt"]


def test_remote_add_and_heredoc_are_skipped():
    text = ("ADD https://example.invalid/x.tgz /x\n"
            "ADD git@github.com:o/r.git /r\n"
            "COPY <<EOF /etc/x\nhello\nEOF\n")
    assert ri.copy_sources(text) == []


def test_leading_dot_slash_and_trailing_slash_are_normalised():
    assert ri.copy_sources("COPY ./scripts/ /s\nCOPY . /all\n") == ["scripts", "."]


def test_lowercase_instruction_is_recognised():
    assert ri.copy_sources("copy x.conf /etc/x.conf\n") == ["x.conf"]


def test_unresolvable_variable_fails_instead_of_guessing():
    try:
        ri.copy_sources("COPY ${SRC}/x /x\n")
    except ri.InputError as error:
        assert "variable" in str(error)
    else:
        raise AssertionError("a variable source must fail, not be skipped")


def test_copy_without_destination_fails():
    try:
        ri.copy_sources("COPY lonely\n")
    except ri.InputError:
        pass
    else:
        raise AssertionError("expected InputError")


# ---------------------------------------------------------------------------
# Change detection against a throwaway repository
# ---------------------------------------------------------------------------

def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def write(repo, path, text):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)


def fixture_repo():
    """A repository shaped like this one, every image released at v1.0.0."""
    repo = pathlib.Path(tempfile.mkdtemp())
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "t@example.invalid")
    git(repo, "config", "user.name", "t")
    git(repo, "config", "commit.gpgsign", "false")
    git(repo, "config", "tag.gpgsign", "false")
    write(repo, "Dockerfile.python-base",
          "FROM x\nCOPY --chown=nonroot:nonroot scripts/harden-pip-vendor.py /tmp/h.py\n")
    write(repo, "Dockerfile.nodejs-base", "FROM y\nRUN true\n")
    write(repo, "Dockerfile.nginx-base", "FROM z AS b\nCOPY --from=b /a /a\nCOPY nginx.conf /etc/n\n")
    write(repo, "deprecated.Dockerfile.old", "FROM retired\n")
    for image in ("python-base", "nodejs-base", "nginx-base"):
        write(repo, f"tests/container-structure/{image}.yaml", "schemaVersion: 2.0.0\n")
    write(repo, "scripts/harden-pip-vendor.py", "print('v1')\n")
    write(repo, "nginx.conf", "events {}\n")
    write(repo, "trivy.yaml", "severity: [MEDIUM]\n")
    write(repo, ".github/workflows/publish-base-images.yml", "name: publish\n")
    write(repo, "README.md", "# readme\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    for image in ("python-base", "nodejs-base", "nginx-base"):
        git(repo, "tag", f"release/{image}/v1.0.0")
    return repo


def change(repo, path, text="changed\n"):
    write(repo, path, text)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", f"change {path}")


def changed(repo):
    return ri.changed_images(repo, log=io.StringIO())


def test_only_dockerfiles_at_the_root_are_images():
    assert ri.images(fixture_repo()) == ["nginx-base", "nodejs-base", "python-base"]


def test_nothing_changed_releases_nothing():
    assert changed(fixture_repo()) == []


def test_a_copied_script_alone_releases_its_image():
    repo = fixture_repo()
    change(repo, "scripts/harden-pip-vendor.py", "print('v2')\n")
    assert changed(repo) == ["python-base"]


def test_a_change_owned_by_one_image_releases_only_that_image():
    repo = fixture_repo()
    change(repo, "tests/container-structure/nodejs-base.yaml", "schemaVersion: 2.0.0\n# x\n")
    assert changed(repo) == ["nodejs-base"]


def test_a_shared_input_releases_every_image():
    repo = fixture_repo()
    change(repo, "trivy.yaml", "severity: [LOW]\n")
    assert changed(repo) == ["nginx-base", "nodejs-base", "python-base"]


def test_the_publish_workflow_is_a_shared_input():
    repo = fixture_repo()
    change(repo, ".github/workflows/publish-base-images.yml", "name: publish v2\n")
    assert changed(repo) == ["nginx-base", "nodejs-base", "python-base"]


def test_a_readme_change_releases_nothing():
    repo = fixture_repo()
    change(repo, "README.md", "# readme v2\n")
    assert changed(repo) == []


def test_baseline_is_the_newest_release_not_the_previous_commit():
    repo = fixture_repo()
    change(repo, "nginx.conf", "events { worker_connections 1; }\n")
    change(repo, "README.md", "# unrelated later commit\n")
    # The nginx change is two commits back; a before/after diff of the last
    # push would miss it, the release tag does not.
    assert changed(repo) == ["nginx-base"]
    git(repo, "tag", "release/nginx-base/v1.0.1")
    assert changed(repo) == []


def test_newest_release_is_chosen_by_version_not_by_name():
    repo = fixture_repo()
    for version in ("v1.0.9", "v1.0.10", "v1.0.2"):
        git(repo, "tag", f"release/nodejs-base/{version}")
    assert ri.latest_release(repo, "nodejs-base") == "release/nodejs-base/v1.0.10"


def test_tags_of_a_similarly_named_image_are_not_its_baseline():
    repo = fixture_repo()
    write(repo, "Dockerfile.nodejs-base-22", "FROM y\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "new image")
    git(repo, "tag", "release/nodejs-base-22/v9.9.9")
    assert ri.latest_release(repo, "nodejs-base") == "release/nodejs-base/v1.0.0"


def test_an_image_never_released_is_released():
    repo = fixture_repo()
    change(repo, "Dockerfile.wolfi-base", "FROM w\n")
    assert "wolfi-base" in changed(repo)


def test_a_git_failure_is_an_error_not_an_empty_result():
    repo = fixture_repo()
    try:
        ri.changed_inputs(repo, "python-base", head="no-such-revision")
    except RuntimeError as error:
        assert "git diff" in str(error)
    else:
        raise AssertionError("a git failure must raise")


def test_cli_prints_json_and_fails_closed():
    repo = fixture_repo()
    change(repo, "scripts/harden-pip-vendor.py", "print('v3')\n")
    script = pathlib.Path(__file__).with_name("release-inputs.py")
    ok = subprocess.run([sys.executable, str(script), "changed"], cwd=repo,
                        capture_output=True, text=True, check=False)
    assert ok.returncode == 0 and ok.stdout.strip() == '["python-base"]', ok
    change(repo, "Dockerfile.nodejs-base", "FROM y\nCOPY $X /x\n")
    bad = subprocess.run([sys.executable, str(script), "changed"], cwd=repo,
                         capture_output=True, text=True, check=False)
    assert bad.returncode == 1 and bad.stdout == "", bad


if __name__ == "__main__":
    # Runnable without pytest, so CI needs no extra dependency.
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    for name, fn in tests:
        fn()
        print(f"ok   {name}")
    print(f"{len(tests)} passed")
