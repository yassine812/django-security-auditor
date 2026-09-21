"""Source acquisition: local folders, ZIP archives, git clones (spec 3-5)."""
import subprocess
from pathlib import Path

import pytest

from apps.projects.sources import (acquire_github, acquire_local, acquire_zip,
                                   copy_to_workspace)


@pytest.fixture()
def git_remote(tmp_path):
    """Local bare-ish repo used as a stand-in for GitHub (no network needed)."""
    origin = tmp_path / "origin"
    origin.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(origin)], check=True)
    subprocess.run(["git", "-C", str(origin), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(origin), "config", "user.name", "t"], check=True)
    (origin / "manage.py").write_text("# django\n")
    subprocess.run(["git", "-C", str(origin), "add", "."], check=True)
    subprocess.run(["git", "-C", str(origin), "commit", "-qm", "init"], check=True)
    sha = subprocess.run(["git", "-C", str(origin), "rev-parse", "HEAD"],
                         capture_output=True, text=True).stdout.strip()
    return str(origin), sha


def test_local_acquisition(vulnerable_app):
    info = acquire_local(vulnerable_app)
    assert info["path"].endswith("vulnerable_app")


def test_local_missing_raises(tmp_path):
    with pytest.raises(RuntimeError):
        acquire_local(str(tmp_path / "missing"))


def test_zip_acquisition(tmp_path, vulnerable_app):
    import shutil
    archive = tmp_path / "proj.zip"
    shutil.make_archive(str(archive)[:-4], "zip", root_dir=vulnerable_app)
    info = acquire_zip(str(archive), str(tmp_path / "out"))
    assert (Path(info["path"]) / "manage.py").exists() or \
        any(Path(info["path"]).rglob("manage.py"))


def test_github_clone_local_remote(tmp_path, git_remote):
    origin, sha = git_remote
    info = acquire_github(f"file://{origin}", str(tmp_path / "clone"), branch="main")
    assert info["commit_sha"] == sha
    assert (Path(info["path"]) / "manage.py").exists()
    assert info["branch"] == "main"


def test_copy_to_workspace_skips_git(tmp_path, git_remote):
    origin, _ = git_remote
    dest = copy_to_workspace(origin, str(tmp_path / "ws"))
    assert not (Path(dest) / ".git").exists()
    assert (Path(dest) / "manage.py").exists()
