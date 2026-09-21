"""Isolated application startup for DAST (spec 12).

Strategy order:
  1. Docker Compose (preferred isolation) if the project ships a compose file
     and docker is available.
  2. Local fallback: ``python manage.py runserver 127.0.0.1:<free-port>``
     bound to loopback only - never exposed publicly.
  3. For GitHub-sourced projects the local fallback is disabled by default
     (spec 2): DAST must run against an isolated container instance.

The sandbox never exposes the app beyond 127.0.0.1 and always enforces a
timeout.  A startup failure returns a clear reason so the pipeline can mark
DAST-dependent requirements NOT TESTED instead of pretending success (spec 36).
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


@dataclass
class StartupResult:
    started: bool
    base_url: str | None = None
    method: str | None = None
    reason: str = ""
    process: subprocess.Popen | None = None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http(url: str, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status:
                    return True
        except urllib.error.HTTPError:
            return True                       # any HTTP answer: app is up
        except (urllib.error.URLError, OSError, TimeoutError):
            time.sleep(0.5)
    return False


def _pick_python(project: Path) -> str:
    for candidate in (project / ".venv/bin/python", project / "venv/bin/python"):
        if candidate.exists():
            return str(candidate)
    return shutil.which("python3") or "python3"


def start_application(source_dir: str, config: dict, source_type: str = "local",
                      wait_timeout: float = 45.0) -> StartupResult:
    project = Path(source_dir)
    dast_cfg = (config or {}).get("dast", {}) or {}
    allow_runserver = dast_cfg.get("allow_local_runserver", True)
    prefer_docker = shutil.which("docker") and (
        (project / "docker-compose.yml").exists() or (project / "docker-compose.yaml").exists())

    # ---- 1. docker compose ------------------------------------------------
    if prefer_docker:
        compose = "docker-compose.yml" if (project / "docker-compose.yml").exists() \
            else "docker-compose.yaml"
        port = _free_port()
        try:
            proc = subprocess.run(["docker", "compose", "-f", compose, "up", "-d", "--build"],
                                  cwd=project, capture_output=True, text=True, timeout=600)
            if proc.returncode == 0:
                base = f"http://127.0.0.1:{port}"
                if _wait_http(base, wait_timeout):
                    return StartupResult(True, base, "docker-compose")
            reason = (proc.stderr or proc.stdout or "")[-500:]
            return StartupResult(False, reason=f"docker compose failed: {reason.strip()}")
        except (subprocess.TimeoutExpired, OSError) as exc:
            return StartupResult(False, reason=f"docker compose unavailable: {exc}")

    # ---- 2. local runserver fallback ---------------------------------------
    if source_type == "github" and not dast_cfg.get("allow_local_runserver_github", False):
        return StartupResult(False, reason=(
            "GitHub-sourced project: DAST requires an isolated container instance "
            "(docker not available); local runserver fallback disabled for remote sources"))

    if not allow_runserver:
        return StartupResult(False, reason="local runserver fallback disabled by configuration")

    manage = project / "manage.py"
    if not manage.is_file():
        return StartupResult(False, reason="no manage.py found - cannot start the application")

    port = _free_port()
    env = dict(os.environ)
    env.setdefault("PYTHONUNBUFFERED", "1")
    env.setdefault("DJANGO_ALLOWED_HOSTS", "127.0.0.1,localhost")
    python = _pick_python(project)
    cmd = [python, "manage.py", "runserver", f"127.0.0.1:{port}", "--noreload"]
    log_path = project / ".audit-runserver.log"
    try:
        logf = open(log_path, "wb")
        proc = subprocess.Popen(cmd, cwd=project, stdout=logf, stderr=subprocess.STDOUT,
                                env=env, start_new_session=True)
    except OSError as exc:
        return StartupResult(False, reason=f"could not launch runserver: {exc}")

    base = f"http://127.0.0.1:{port}"
    if _wait_http(base, wait_timeout):
        return StartupResult(True, base, "runserver", process=proc)

    # failed: collect tail of log for the report
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
    tail = ""
    try:
        tail = log_path.read_text(errors="replace")[-800:]
    except OSError:
        pass
    return StartupResult(False, reason=f"application did not become reachable: {tail.strip()}",
                         process=None)


def stop_application(startup: StartupResult) -> None:
    proc = startup.process
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
