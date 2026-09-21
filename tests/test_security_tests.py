"""Automated security test framework tests (spec 14)."""
import pytest

from security_tests.framework import TestContext
from security_tests.tests import ALL_TESTS, TestRunner
from tests.helpers import FakeDjangoServer

ENDPOINTS = [
    {"method": "GET", "path": "/search/", "view": "search"},
    {"method": "GET", "path": "/doc/", "view": "doc"},
    {"method": "GET", "path": "/go/", "view": "go"},
    {"method": "POST", "path": "/search/", "view": "search"},
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


def runner_results(base_url, endpoints=ENDPOINTS, accounts=None):
    ctx = TestContext(base_url=base_url, endpoints=endpoints, accounts=accounts or {})
    executions, evidence, findings = TestRunner().run_all(ctx)
    return {e["test_id"]: e for e in executions}, evidence, findings


def test_all_tests_have_metadata():
    for t in ALL_TESTS:
        assert t.id and t.name and t.requirement_ids and t.severity


def test_without_runtime_everything_not_tested():
    results, evidence, findings = runner_results(None)
    assert all(r["status"] == "NOT_TESTED" for r in results.values())
    assert not findings


def test_xss_test_fails_on_vulnerable_app(vuln_server):
    results, _, findings = runner_results(vuln_server.url)
    assert results["XSS-001"]["status"] == "FAIL"
    assert any("Reflected XSS probes" in f.title for f in findings)


def test_xss_test_passes_on_secure_app(secure_server):
    results, evidence, _ = runner_results(secure_server.url)
    assert results["XSS-001"]["status"] == "PASS"
    assert any(e.polarity == "ok" and "TEST-XSS-001" in e.rule_id for e in evidence)


def test_sqli_test_fails_on_vulnerable_app(vuln_server):
    results, _, _ = runner_results(vuln_server.url)
    assert results["SQLI-001"]["status"] == "FAIL"


def test_sqli_test_passes_on_secure_app(secure_server):
    results, _, _ = runner_results(secure_server.url)
    assert results["SQLI-001"]["status"] == "PASS"


def test_traversal_test_fails_on_vulnerable_app(vuln_server):
    results, _, _ = runner_results(vuln_server.url)
    assert results["TRAVERSAL-001"]["status"] == "FAIL"


def test_redirect_test_fails_on_vulnerable_app(vuln_server):
    results, _, _ = runner_results(vuln_server.url)
    assert results["REDIR-001"]["status"] == "FAIL"


def test_redirect_test_passes_on_secure_app(secure_server):
    results, _, _ = runner_results(secure_server.url)
    assert results["REDIR-001"]["status"] == "PASS"


def test_csrf_test_fails_without_protection(vuln_server):
    results, _, _ = runner_results(vuln_server.url)
    assert results["CSRF-001"]["status"] == "FAIL"


def test_csrf_test_passes_with_protection(secure_server):
    results, _, _ = runner_results(secure_server.url)
    assert results["CSRF-001"]["status"] == "PASS"


def test_account_dependent_tests_not_tested_without_accounts(vuln_server):
    results, _, _ = runner_results(vuln_server.url)
    for tid in ("AUTHZ-V-001", "AUTHZ-H-001", "UPLOAD-001"):
        assert results[tid]["status"] == "NOT_TESTED"


def test_executions_record_expected_vs_actual(vuln_server):
    results, _, _ = runner_results(vuln_server.url)
    for r in results.values():
        assert r["expected"] and r["actual"]


def test_findings_map_to_requirements(vuln_server):
    _, _, findings = runner_results(vuln_server.url)
    assert findings
    for f in findings:
        assert f.requirement_ids and f.sources == ["automated"]
