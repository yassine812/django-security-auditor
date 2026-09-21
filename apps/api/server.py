"""REST API + dashboard server (FastAPI).

Endpoints (spec 34):
    POST /api/auth/token            obtain a bearer token
    GET  /api/projects              project registry (derived from audits)
    POST /api/projects              register project {name, source_type, path|repo_url}
    GET  /api/audits                list audits
    POST /api/audits                create + queue full audit
    GET  /api/audits/{id}           audit state
    GET  /api/audits/{id}/requirements | /findings | /endpoints | /jobs | /logs
    POST /api/audits/{id}/retest    queue a retest
    GET  /api/reports/{id}/{fmt}    download report (html|json|csv|pdf)
    GET  /api/jobs                  worker queue status

Authentication: Bearer tokens (scrypt-hashed users, RBAC).  The dashboard is
served at / (single page, calls this API).
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from apps.audits.models import AuditStore
from apps.audits.pipeline import AuditPipeline
from apps.audits.retest import run_retest
from apps.users.auth import AuthError, UserStore
from worker.queue import JobQueue

FRONTEND = Path(__file__).resolve().parents[2] / "frontend" / "dashboard.html"
bearer = HTTPBearer(auto_error=False)


def build_app(store: AuditStore, config_path: str | None = None,
              workdir: str | None = None) -> FastAPI:
    workdir = workdir or str(store.root.parent)
    users = UserStore(workdir)
    if not users._read()["users"]:                    # bootstrap default admin
        users.create_user("admin", "admin-audit-2026", "admin")
    queue = JobQueue(max_workers=2)
    app = FastAPI(title="Django Security Auditor", version="0.1.0")

    def auth(request: Request, permission: str = "read"):
        creds: Optional[HTTPAuthorizationCredentials] = None
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            creds = HTTPAuthorizationCredentials(scheme="bearer",
                                                 credentials=header.split(" ", 1)[1])
        try:
            return users.require(creds.credentials if creds else None, permission)
        except AuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc))

    # ---- auth ---------------------------------------------------------
    @app.post("/api/auth/token")
    def token(body: dict):
        try:
            tok = users.verify(body.get("username", ""), body.get("password", ""))
        except AuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        users.audit_log("auth.login", {"username": body.get("username")})
        return {"token": tok}

    # ---- projects -------------------------------------------------------
    @app.get("/api/projects")
    def projects(request: Request):
        auth(request)
        seen = {}
        for item in store.list_audits():
            try:
                audit = store.load(item["id"])
                p = audit.project
                seen.setdefault(p.get("name"), p)
            except FileNotFoundError:
                continue
        return {"projects": list(seen.values())}

    @app.post("/api/projects")
    def create_project(body: dict, request: Request):
        user, role = auth(request, "create_audit")
        users.audit_log("project.create", {"user": user, "project": body.get("name")})
        return {"status": "registered", "project": body}

    # ---- audits -----------------------------------------------------------
    @app.get("/api/audits")
    def audits(request: Request):
        auth(request)
        return {"audits": store.list_audits()}

    @app.post("/api/audits")
    def create_audit(body: dict, request: Request):
        user, role = auth(request, "create_audit")
        project = body.get("project") or {}
        if not project.get("path") and not project.get("repo_url"):
            raise HTTPException(status_code=400, detail="project.path or repo_url required")
        if project.get("source_type") == "github":
            from apps.projects.sources import acquire_github
            import datetime as dt
            dest = str(Path(store.root) / f"clone-{dt.datetime.now().strftime('%H%M%S%f')}")
            info = acquire_github(project["repo_url"], dest, branch=project.get("branch"),
                                  token=project.get("token"))
            project = {"name": project.get("name") or Path(project["repo_url"]).name,
                       "source_type": "github", "path": info["path"],
                       "repo_url": info["repo_url"], "branch": info["branch"],
                       "commit_sha": info["commit_sha"]}
        else:
            project.setdefault("source_type", "local")
            project.setdefault("name", Path(project["path"]).name)
            project["path"] = str(Path(project["path"]).expanduser().resolve())

        pipeline = AuditPipeline(store, config_path)
        audit = pipeline.create_audit(project,
                                      authorization_confirmed=bool(
                                          body.get("authorization_confirmed")))
        users.audit_log("audit.create", {"user": user, "audit_id": audit.id})
        queue.submit("full-audit", pipeline.run_full, audit)
        return {"audit_id": audit.id, "status": "QUEUED"}

    @app.get("/api/audits/{audit_id}")
    def audit_detail(audit_id: str, request: Request):
        auth(request)
        try:
            audit = store.load(audit_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="audit not found")
        return audit.to_dict()

    def _sub(audit_id: str, attr: str, request: Request):
        auth(request)
        try:
            audit = store.load(audit_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="audit not found")
        return {attr: getattr(audit, attr)}

    @app.get("/api/audits/{audit_id}/requirements")
    def audit_requirements(audit_id: str, request: Request):
        return _sub(audit_id, "requirement_results", request)

    @app.get("/api/audits/{audit_id}/findings")
    def audit_findings(audit_id: str, request: Request):
        return _sub(audit_id, "findings", request)

    @app.get("/api/audits/{audit_id}/endpoints")
    def audit_endpoints(audit_id: str, request: Request):
        return _sub(audit_id, "endpoints", request)

    @app.get("/api/audits/{audit_id}/jobs")
    def audit_jobs(audit_id: str, request: Request):
        return _sub(audit_id, "jobs", request)

    @app.get("/api/audits/{audit_id}/logs")
    def audit_logs(audit_id: str, request: Request):
        return _sub(audit_id, "logs", request)

    @app.get("/api/audits/{audit_id}/evidence")
    def audit_evidence(audit_id: str, request: Request):
        return _sub(audit_id, "evidence", request)

    @app.post("/api/audits/{audit_id}/retest")
    def retest(audit_id: str, body: dict, request: Request):
        user, role = auth(request, "retest")
        path = body.get("path")
        if not path:
            raise HTTPException(status_code=400, detail="path required")
        users.audit_log("audit.retest", {"user": user, "audit_id": audit_id})
        job = queue.submit("retest", run_retest, store, audit_id, path,
                           bool(body.get("authorization_confirmed")), config_path)
        return {"job_id": job.job_id, "status": "QUEUED"}

    @app.get("/api/jobs")
    def jobs(request: Request):
        auth(request)
        return {"jobs": queue.list()}

    # ---- reports -----------------------------------------------------------
    @app.get("/api/reports/{audit_id}/{fmt}")
    def report(audit_id: str, fmt: str, request: Request):
        auth(request)
        store.dir_for(audit_id)
        base = store.root / audit_id / "reports"
        names = {"html": "report.html", "json": "report.json", "pdf": "report.pdf",
                 "csv": "findings.csv"}
        if fmt not in names:
            raise HTTPException(status_code=400, detail="format must be html|json|pdf|csv")
        f = base / names[fmt]
        if not f.exists():
            raise HTTPException(status_code=404, detail="report not generated yet")
        return FileResponse(f)

    # ---- dashboard ------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    @app.get("/audits/{rest:path}", response_class=HTMLResponse)
    def dashboard():
        if FRONTEND.exists():
            return FRONTEND.read_text(encoding="utf-8")
        return "<h1>dashboard missing</h1>"

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        return JSONResponse(status_code=500, content={"detail": str(exc)[:300]})

    return app
