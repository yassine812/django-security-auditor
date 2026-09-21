"""Platform auth/RBAC (spec 34/38) and worker queue tests."""
import time

import pytest

from apps.users.auth import AuthError, UserStore
from worker.queue import JobQueue


@pytest.fixture()
def users(tmp_path):
    return UserStore(str(tmp_path))


def test_create_and_login(users):
    users.create_user("alice", "pw12345", "analyst")
    token = users.verify("alice", "pw12345")
    assert len(token) == 64


def test_bad_password_rejected(users):
    users.create_user("alice", "pw12345", "analyst")
    with pytest.raises(AuthError):
        users.verify("alice", "wrong")


def test_rbac_permissions(users):
    users.create_user("v", "pw", "viewer")
    token = users.create_token("v")
    users.require(token, "read")
    with pytest.raises(AuthError):
        users.require(token, "create_audit")


def test_admin_can_create_audits(users):
    users.create_user("a", "pw", "admin")
    token = users.create_token("a")
    assert users.require(token, "create_audit")[1] == "admin"


def test_invalid_token_rejected(users):
    with pytest.raises(AuthError):
        users.require("bogus", "read")


def test_audit_log_written(users, tmp_path):
    users.audit_log("test.action", {"k": "v"})
    assert users.log_path.exists()
    assert "test.action" in users.log_path.read_text()


def test_users_file_not_world_readable(users, tmp_path):
    import os, stat
    users.create_user("a", "pw", "admin")
    mode = stat.S_IMODE(os.stat(users.path).st_mode)
    assert mode & 0o077 == 0 or mode == 0o600


def test_job_queue_runs_and_tracks():
    q = JobQueue(max_workers=1)
    ran = []
    job = q.submit("test", lambda: ran.append(1))
    deadline = time.time() + 5
    while q.get(job.job_id).status not in ("SUCCESS", "FAILED") and time.time() < deadline:
        time.sleep(0.05)
    assert ran == [1]
    assert q.get(job.job_id).status == "SUCCESS"


def test_job_queue_captures_failure():
    q = JobQueue(max_workers=1)
    def boom():
        raise RuntimeError("nope")
    job = q.submit("test", boom)
    deadline = time.time() + 5
    while q.get(job.job_id).status != "FAILED" and time.time() < deadline:
        time.sleep(0.05)
    assert q.get(job.job_id).status == "FAILED"
    assert "nope" in q.get(job.job_id).error


def test_job_queue_lists_jobs():
    q = JobQueue()
    q.submit("a", lambda: None)
    assert q.list()[0]["kind"] == "a"
