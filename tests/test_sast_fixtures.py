"""Fixture-level SAST verification: vulnerable app detected, secure app clean."""
import pytest

from scanners.sast.scanner import sast_only_scan


@pytest.fixture(scope="module")
def vuln_result(vulnerable_app):
    return sast_only_scan(vulnerable_app)


@pytest.fixture(scope="module")
def secure_result(secure_app):
    return sast_only_scan(secure_app)


def titles(result):
    return [f.title for f in result.findings]


@pytest.mark.parametrize("expected", [
    "Dynamic code execution (eval/exec/compile)",
    "Dynamic SQL via cursor.execute",
    "Shell command execution (os.system/os.popen)",
    "subprocess with shell=True",
    "Pickle deserialization",
    "Unsafe YAML loading",
    "Server-side request with dynamic URL",
    "Redirect to dynamic destination",
    "Dynamic file serving",
    "Server-side template injection risk",
    "Weak hash algorithm (MD5/SHA1)",
    "Insecure temporary file (mktemp)",
    "CSRF exemption",
    "Mass assignment via **request.data",
    "AllowAny permission on API view",
    "Empty permission_classes",
    "Empty authentication_classes",
    "Hardcoded Django SECRET_KEY",
    "Stripe secret key detected",
    "|safe filter in template",
    "autoescape disabled in template",
    "Sensitive field exposed by serializer",
])
def test_vulnerable_app_detects(vuln_result, expected):
    assert any(expected in t for t in titles(vuln_result)), f"missing: {expected}"


def test_vulnerable_app_sql_confirmed(vuln_result):
    sqli = [f for f in vuln_result.findings if "SQL" in f.title]
    assert any(f.confidence in ("Confirmed", "High") for f in sqli)


def test_secure_app_no_critical(secure_result):
    critical = [f for f in secure_result.findings if f.severity == "Critical"]
    assert not critical, [f.title for f in critical]


def test_secure_app_no_confirmed_findings(secure_result):
    confirmed = [f for f in secure_result.findings if f.confidence == "Confirmed"]
    assert not confirmed, [(f.title, f.file, f.line) for f in confirmed]


def test_secure_app_ok_controls(secure_result):
    rules = [e.rule_id for e in secure_result.evidence if e.polarity == "ok"]
    assert "OK-DEFUSEDXML" in rules
    assert "OK-SAFEYAML" in rules
    assert "OK-REDIR" in rules
    assert "OK-SFU" in rules


def test_findings_have_required_fields(vuln_result):
    for f in vuln_result.findings:
        assert f.title and f.severity and f.confidence and f.category
        assert f.cwe and f.owasp
        assert f.requirement_ids, f"{f.title} has no requirement mapping"
        assert f.remediation


def test_evidence_locations_present(vuln_result):
    for e in vuln_result.evidence:
        if e.polarity == "vuln":
            assert e.location.get("file"), e.summary


def test_secrets_masked_in_evidence(vuln_result):
    for e in vuln_result.evidence:
        blob = str(e.location) + e.summary
        assert "insecure-hardcoded-secret-key" not in blob
        assert "sk_live_FAKE0000000000000000" not in blob
