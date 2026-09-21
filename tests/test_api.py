"""REST API tests (spec 34) using FastAPI TestClient."""
import time
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from apps.api.server import build_app
from apps.audits.models import AuditStore


FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("api")
    cfg = tmp / "cfg.yml"
    cfg.write_text(yaml.safe_dump({"scanning": {"dast": False},
                                   "network": {"scan_ports": [1],
                                               "authorized_targets": ["127.0.0.1"]}}))
    store = AuditStore(str(tmp / "wd"))
    app = build_app(store, config_path=str(cfg), workdir=str(tmp))
    client = TestClient(app)
    return client, str(FIXTURES / "vulnerable_app")


def auth_header(client):
    r = client.post("/api/auth/token",
                    json={"username": "admin", "password": "admin-audit-2026"})
    assert r.status_code == 200
    return {"Authorization": "Bearer " + r.json()["token"]}


def test_auth_required(server):
    client, _ = server
    assert client.get("/api/audits").status_code == 401


def test_bad_credentials(server):
    client, _ = server
    r = client.post("/api/auth/token", json={"username": "admin", "password": "nope"})
    assert r.status_code == 401


def test_token_flow_and_list(server):
    client, _ = server
    h = auth_header(client)
    assert client.get("/api/audits", headers=h).status_code == 200


def test_dashboard_served(server):
    client, _ = server
    r = client.get("/")
    assert r.status_code == 200
    assert "Django Security" in r.text


def test_create_and_fetch_audit(server):
    client, app_path = server
    h = auth_header(client)
    r = client.post("/api/audits", headers=h, json={
        "project": {"name": "vuln", "source_type": "local", "path": app_path},
        "authorization_confirmed": True})
    assert r.status_code == 200
    audit_id = r.json()["audit_id"]

    deadline = time.time() + 120
    state = None
    while time.time() < deadline:
        state = client.get(f"/api/audits/{audit_id}", headers=h).json()
        if state.get("status") == "COMPLETE":
            break
        time.sleep(1)
    assert state["status"] == "COMPLETE"
    assert len(state["requirement_results"]) == 137

    findings = client.get(f"/api/audits/{audit_id}/findings", headers=h).json()["findings"]
    assert findings
    reqs = client.get(f"/api/audits/{audit_id}/requirements", headers=h).json()
    assert len(reqs["requirement_results"]) == 137
    endpoints = client.get(f"/api/audits/{audit_id}/endpoints", headers=h).json()
    assert endpoints["endpoints"]
    jobs = client.get(f"/api/audits/{audit_id}/jobs", headers=h).json()
    assert any(j["name"] == "sast" for j in jobs["jobs"])
    logs = client.get(f"/api/audits/{audit_id}/logs", headers=h).json()
    assert logs["logs"]

    report = client.get(f"/api/reports/{audit_id}/html", headers=h)
    assert report.status_code == 200
    assert "Executive summary" in report.text
    pdf = client.get(f"/api/reports/{audit_id}/pdf", headers=h)
    assert pdf.status_code == 200

    projects = client.get("/api/projects", headers=h).json()
    assert any(p["name"] == "vuln" for p in projects["projects"])


def test_missing_project_rejected(server):
    client, _ = server
    h = auth_header(client)
    r = client.post("/api/audits", headers=h, json={"project": {}})
    assert r.status_code == 400


def test_unknown_audit_404(server):
    client, _ = server
    h = auth_header(client)
    assert client.get("/api/audits/nope", headers=h).status_code == 404


def test_jobs_endpoint(server):
    client, _ = server
    h = auth_header(client)
    assert "jobs" in client.get("/api/jobs", headers=h).json()
