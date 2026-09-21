"""Django settings scanner checks (spec 8)."""
import textwrap

import pytest

from apps.projects.discovery import discover_project
from scanners.base import AuditContext
from scanners.configuration.django_settings import (DjangoSettingsScanner,
                                                    extract_settings)


def run(src):
    ctx = AuditContext(source_dir=src)
    ctx.profile = discover_project(src)
    ctx.settings_values = None
    return DjangoSettingsScanner().safe_run(ctx)


def polarities(result):
    return {e.rule_id: e.polarity for e in result.evidence}


def test_vulnerable_settings_fail(vulnerable_app):
    r = run(vulnerable_app)
    p = polarities(r)
    for check in ("CFG-DEBUG", "CFG-SECRETKEY", "CFG-ALLOWED-HOSTS", "CFG-CSRF-SECURE",
                  "CFG-SESS-SECURE", "CFG-SESS-HTTPONLY", "CFG-SSL-REDIRECT", "CFG-HSTS",
                  "CFG-NOSNIFF", "CFG-XFO", "CFG-REFERRER", "CFG-CSRFMW", "CFG-CORS",
                  "CFG-PWVALID", "CFG-DB-CREDS", "CFG-DRF-AUTH", "CFG-DRF-PERM",
                  "CFG-SESS-AGE"):
        assert p.get(check) == "vuln", f"{check} should fail"


def test_secure_settings_pass(secure_app):
    r = run(secure_app)
    vulns = [e for e in r.evidence if e.polarity == "vuln"]
    assert not vulns, [e.summary for e in vulns]
    p = polarities(r)
    for check in ("CFG-DEBUG", "CFG-ALLOWED-HOSTS", "CFG-SESS-SECURE", "CFG-HSTS",
                  "CFG-CSRFMW", "CFG-SECMW", "CFG-DRF-AUTH", "CFG-DRF-PERM",
                  "CFG-THROTTLE", "CFG-PAGINATION", "CFG-PWHASH", "CFG-PWVALID"):
        assert p.get(check) == "ok", f"{check} should pass"


def test_settings_values_masked(vulnerable_app):
    r = run(vulnerable_app)
    snap = r.data["settings"]
    assert "insecure-hardcoded-secret-key" not in str(snap.get("SECRET_KEY"))
    assert "supersecretpassword123" not in str(snap)


def test_env_secret_key_is_ok(tmp_path):
    (tmp_path / "settings.py").write_text(textwrap.dedent("""
        import os
        SECRET_KEY = os.environ["SECRET_KEY"]
        DEBUG = False
        ALLOWED_HOSTS = ["a.example.com"]
    """))
    state = extract_settings(str(tmp_path))
    assert state.get("DEBUG") is False
    sk = state.get("SECRET_KEY")
    assert isinstance(sk, dict) and sk["__env__"] == "SECRET_KEY"


def test_debug_true_detected(tmp_path):
    (tmp_path / "settings.py").write_text("DEBUG = True\nALLOWED_HOSTS = ['*']\n")
    ctx = AuditContext(source_dir=str(tmp_path))
    ctx.profile = {"dependencies": [], "settings_files": ["settings.py"]}
    r = DjangoSettingsScanner().safe_run(ctx)
    ids = {(e.rule_id, e.polarity) for e in r.evidence}
    assert ("CFG-DEBUG", "vuln") in ids
    assert ("CFG-ALLOWED-HOSTS", "vuln") in ids


def test_no_settings_module_skipped(tmp_path):
    ctx = AuditContext(source_dir=str(tmp_path))
    ctx.profile = {"dependencies": []}
    r = DjangoSettingsScanner().safe_run(ctx)
    assert r.status == "SKIPPED"


def test_missing_csrf_middleware_high(tmp_path):
    (tmp_path / "settings.py").write_text(
        "DEBUG = False\nALLOWED_HOSTS = ['a.example.com']\nMIDDLEWARE = []\n")
    ctx = AuditContext(source_dir=str(tmp_path))
    ctx.profile = {"dependencies": [], "settings_files": ["settings.py"]}
    r = DjangoSettingsScanner().safe_run(ctx)
    csrf = [e for e in r.evidence if e.rule_id == "CFG-CSRFMW"]
    assert csrf and csrf[0].polarity == "vuln" and csrf[0].requirement_ids == ["REQ-009"]


def test_production_overrides_base(tmp_path):
    (tmp_path / "settings_base.py").write_text("DEBUG = True\n")
    (tmp_path / "settings_production.py").write_text("DEBUG = False\n")
    state = extract_settings(str(tmp_path))
    assert state.get("DEBUG") is False


def test_findings_created_for_failures(vulnerable_app):
    r = run(vulnerable_app)
    assert r.findings
    assert all(f.sources == ["configuration"] for f in r.findings)
    assert all(f.dedup_key.startswith("config:") for f in r.findings)


def test_drf_allowany_default_flagged(tmp_path):
    (tmp_path / "settings.py").write_text(
        "DEBUG=False\nALLOWED_HOSTS=['a.example.com']\n"
        "INSTALLED_APPS=['rest_framework']\n"
        "REST_FRAMEWORK={'DEFAULT_PERMISSION_CLASSES': "
        "['rest_framework.permissions.AllowAny']}\n")
    ctx = AuditContext(source_dir=str(tmp_path))
    ctx.profile = {"dependencies": [{"name": "djangorestframework", "specifier": "==3.15",
                                     "line": ""}], "settings_files": ["settings.py"]}
    r = DjangoSettingsScanner().safe_run(ctx)
    ids = {(e.rule_id, e.polarity) for e in r.evidence}
    assert ("CFG-DRF-PERM", "vuln") in ids
