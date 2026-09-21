"""Audit state models (spec 33).

The canonical production deployment uses PostgreSQL (see docs/schema.sql);
this module defines the same entities as Python objects with JSON persistence
so the platform also runs with zero external services (CLI / air-gapped use).
Every audit gets an isolated workspace:

    <workdir>/audits/<audit_id>/
        source/        cloned/extracted project (for github/zip inputs)
        audit.json     full audit state
        reports/       generated reports
        logs/          structured scan logs
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_audit_id() -> str:
    return f"audit-{uuid.uuid4().hex[:8]}"


@dataclass
class Project:
    name: str
    source_type: str                      # github | local | zip
    path: str                             # absolute source path to scan
    repo_url: Optional[str] = None
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    created_at: str = field(default_factory=now_iso)
    profile: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        return cls(**d)


@dataclass
class Audit:
    """Complete state of one audit run."""
    id: str
    project: dict
    created_at: str = field(default_factory=now_iso)
    finished_at: Optional[str] = None
    status: str = "CREATED"               # CREATED|RUNNING|COMPLETE|FAILED
    config: dict = field(default_factory=dict)
    authorization_confirmed: bool = False
    jobs: list = field(default_factory=list)          # ScanJob dicts
    profile: dict = field(default_factory=dict)
    endpoints: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    requirement_results: list = field(default_factory=list)
    test_executions: list = field(default_factory=list)
    settings_values: dict = field(default_factory=dict)
    dependencies_report: dict = field(default_factory=dict)
    network_report: dict = field(default_factory=dict)
    dast_report: dict = field(default_factory=dict)
    score: dict = field(default_factory=dict)
    sast_data: dict = field(default_factory=dict)
    report_paths: dict = field(default_factory=dict)
    logs: list = field(default_factory=list)
    retest_of: Optional[str] = None
    comparison: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)

    def log(self, level: str, message: str) -> None:
        self.logs.append({"ts": now_iso(), "level": level, "message": message})

    def job(self, name: str) -> Optional[dict]:
        for j in self.jobs:
            if j["name"] == name:
                return j
        return None

    def set_job(self, name: str, status: str, error: Optional[str] = None) -> dict:
        job = self.job(name)
        if job is None:
            job = {"name": name, "status": status, "error": None,
                   "started_at": now_iso(), "finished_at": None}
            self.jobs.append(job)
        else:
            job["status"] = status
            if status == "RUNNING" and not job.get("started_at"):
                job["started_at"] = now_iso()
        if status in ("SUCCESS", "FAILED", "SKIPPED"):
            job["finished_at"] = now_iso()
        if error is not None:
            job["error"] = error
        return job

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        return cls(**d)


class AuditStore:
    """File-backed persistence: one directory per audit under the workdir."""

    def __init__(self, workdir: str):
        self.root = Path(workdir) / "audits"
        self.root.mkdir(parents=True, exist_ok=True)

    def dir_for(self, audit_id: str) -> Path:
        p = self.root / audit_id
        p.mkdir(parents=True, exist_ok=True)
        return p

    def save(self, audit: Audit) -> Path:
        d = self.dir_for(audit.id)
        (d / "audit.json").write_text(json.dumps(audit.to_dict(), indent=2, default=str),
                                      encoding="utf-8")
        self._update_index(audit)
        return d

    def load(self, audit_id: str) -> Audit:
        p = self.root / audit_id / "audit.json"
        if not p.exists():
            raise FileNotFoundError(f"audit {audit_id!r} not found")
        return Audit.from_dict(json.loads(p.read_text(encoding="utf-8")))

    def list_audits(self) -> list[dict]:
        index = self.root / "index.json"
        if index.exists():
            try:
                return json.loads(index.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        # rebuild index from disk
        items = []
        for f in sorted(self.root.glob("*/audit.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                items.append({
                    "id": data["id"], "created_at": data.get("created_at"),
                    "status": data.get("status"),
                    "project": (data.get("project") or {}).get("name"),
                })
            except Exception:
                continue
        return items

    def _update_index(self, audit: Audit) -> None:
        items = [i for i in self.list_audits() if i.get("id") != audit.id]
        items.append({
            "id": audit.id, "created_at": audit.created_at, "status": audit.status,
            "project": (audit.project or {}).get("name"),
        })
        items.sort(key=lambda i: i.get("created_at") or "", reverse=True)
        (self.root / "index.json").write_text(json.dumps(items, indent=2), encoding="utf-8")
