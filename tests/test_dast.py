"""DAST engine tests against an in-process fake Django app (spec 12)."""
import pytest

from scanners.base import AuditContext
from scanners.dast.scanner import DASTScanner
from tests.helpers import FakeDjangoServer

ENDPOINTS = [
    {"method": "GET", "path": "/search/", "view": "search"},
    {"method": "GET", "path": "/doc/", "view": "doc"},
    {"method": "GET", "path": "/go/", "view": "go"},
    {"method": "GET", "path": "/download/", "view": "download"},
]


@pytest.fixture()
def vuln_server():
    srv = FakeDjangoServer(secure=False).start()
    yield srv
    srv.stop()


@pytest.fixture()
def secure_server():
    srv = FakeDjangoServer(secure=True).start()
    yield srv
    srv.stop()


def ctx(base_url, authorized=True):
    c = AuditContext(source_dir=".", config={"scanning": {"dast": True}},
                     authorization_confirmed=authorized)
    c.base_url = base_url
    c.endpoints = ENDPOINTS
    return c


def test_dast_skipped_without_base_url():
    r = DASTScanner().safe_run(AuditContext(source_dir="."))
    assert r.status == "SKIPPED"


def test_dast_skipped_without_authorization(vuln_server):
    r = DASTScanner().safe_run(ctx(vuln_server.url, authorized=False))
    assert r.status == "SKIPPED"


def test_vulnerable_app_findings(vuln_server):
    r = DASTScanner().safe_run(ctx(vuln_server.url))
    rules = {e.rule_id for e in r.evidence if e.polarity == "vuln"}
    assert "DAST-HDR-HSTS" in rules
    assert "DAST-ENV-001" in rules          # .env / .git exposed
    assert "DAST-DEBUG-001" in rules        # debug page
    assert "DAST-XSS-001" in rules          # reflection
    assert "DAST-SQLI-001" in rules         # SQL error disclosure
    assert "DAST-TRAVERSAL-001" in rules    # /etc/passwd content
    assert "DAST-REDIR-001" in rules        # open redirect
    assert "DAST-ADMIN-001" in rules        # anonymous admin
    assert "DAST-DOCS-001" in rules         # swagger exposed


def test_vulnerable_app_cookie_flags(vuln_server):
    r = DASTScanner().safe_run(ctx(vuln_server.url))
    vuln_cookie = [e for e in r.evidence if e.rule_id == "DAST-COOKIE-FLAGS"
                   and e.polarity == "vuln"]
    assert vuln_cookie  # session cookie missing HttpOnly


def test_secure_app_no_findings(secure_server):
    r = DASTScanner().safe_run(ctx(secure_server.url))
    assert not r.findings, [f.title for f in r.findings]


def test_secure_app_ok_headers(secure_server):
    r = DASTScanner().safe_run(ctx(secure_server.url))
    ok_rules = {e.rule_id for e in r.evidence if e.polarity == "ok"}
    assert "DAST-HDR-HSTS" in ok_rules
    assert "DAST-HDR-NOSNIFF" in ok_rules
    assert "DAST-HDR-XFO" in ok_rules
    assert "DAST-DEBUG-001" in ok_rules


def test_liveness_evidence_req136(vuln_server):
    r = DASTScanner().safe_run(ctx(vuln_server.url))
    assert any(e.rule_id == "DAST-HEALTH-001" and e.polarity == "ok"
               and "REQ-136" in e.requirement_ids for e in r.evidence)


def test_findings_carry_endpoint_evidence(vuln_server):
    r = DASTScanner().safe_run(ctx(vuln_server.url))
    for f in r.findings:
        assert f.endpoint or f.proof
        assert f.evidence_ids


def test_dast_data_summary(vuln_server):
    r = DASTScanner().safe_run(ctx(vuln_server.url))
    assert r.data["base_url"] == vuln_server.url
    assert r.data["checks_run"] > 10


def test_dedup_key_per_check(vuln_server):
    r = DASTScanner().safe_run(ctx(vuln_server.url))
    keys = [f.dedup_key for f in r.findings]
    assert len(keys) == len(set(keys))
