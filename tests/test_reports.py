"""Report generation tests (spec 27)."""
import csv
import json

import pytest

from apps.audits.models import Audit, AuditStore
from apps.reports.generator import (generate_all_reports, write_csv, write_html,
                                    write_json, write_pdf)
from apps.reports.pdf import render_pdf


def sample_audit():
    a = Audit(id="audit-test", project={"name": "demo", "source_type": "local",
                                        "path": "/demo"})
    a.jobs = [{"name": "sast", "status": "SUCCESS", "error": None}]
    a.findings = [{
        "id": "F1", "title": "IDOR / Broken Object Level Authorization",
        "description": "User A accessed User B document.",
        "severity": "Critical", "confidence": "Confirmed",
        "category": "Broken Access Control", "cwe": ["CWE-639"],
        "owasp": "A01:2021", "requirement_ids": ["REQ-004"],
        "sources": ["sast", "dast"], "evidence_ids": ["EV-1"],
        "file": "views.py", "line": 42, "endpoint": "/api/documents/26",
        "request": None, "response": None,
        "proof": "GET /api/documents/26 -> 200",
        "remediation": "Enforce object-level authorization and tenant filtering.",
        "status": "OPEN", "dedup_key": "k", "retest_status": None,
        "first_seen": "t0", "last_seen": "t0"}]
    a.requirement_results = [{"requirement_id": "REQ-004", "status": "FAIL",
                              "sources": ["sast", "dast"], "finding_ids": ["F1"],
                              "notes": ["User A accessed User B document"]}]
    a.score = {"score": 64.0, "max": 100,
               "findings_by_severity": {"Critical": 1},
               "requirements_by_status": {"FAIL": 1}, "disclaimer": "x"}
    return a


def test_pdf_renders_valid_header(tmp_path):
    data = render_pdf([("h1", "Title"), ("body", "hello world")], "t")
    assert data.startswith(b"%PDF-1.4")
    assert data.rstrip().endswith(b"%%EOF")
    assert b"/Type /Page" in data


def test_pdf_wraps_long_lines(tmp_path):
    data = render_pdf([("body", "word " * 300)], "t")
    assert b"%%EOF" in data


def test_json_report(tmp_path):
    write_json(sample_audit(), tmp_path / "r.json")
    data = json.loads((tmp_path / "r.json").read_text())
    assert data["findings"][0]["cwe"] == ["CWE-639"]


def test_csv_reports(tmp_path):
    paths = write_csv(sample_audit(), tmp_path)
    assert len(paths) == 2
    rows = list(csv.DictReader(open(paths[0])))
    assert rows[0]["severity"] == "Critical"
    assert rows[0]["cwe"] == "CWE-639"
    req_rows = list(csv.DictReader(open(paths[1])))
    assert req_rows[0]["status"] == "FAIL"


def test_html_report_contains_sections(tmp_path):
    write_html(sample_audit(), tmp_path / "r.html")
    text = (tmp_path / "r.html").read_text()
    for section in ("Executive summary", "Vulnerabilities", "Requirements coverage",
                    "CWE mapping", "OWASP", "Remediation", "Limitations"):
        assert section in text
    assert "IDOR / Broken Object Level Authorization" in text
    assert "is not proof of security" in text.lower() or \
           "not proof of security" in text.lower()


def test_pdf_report_full(tmp_path):
    write_pdf(sample_audit(), tmp_path / "r.pdf")
    data = (tmp_path / "r.pdf").read_bytes()
    assert data.startswith(b"%PDF")


def test_generate_all_reports(tmp_path):
    store = AuditStore(str(tmp_path))
    audit = sample_audit()
    store.dir_for(audit.id)
    paths = generate_all_reports(store, audit)
    assert set(paths) == {"json", "html", "csv", "pdf"}
    from pathlib import Path
    for p in paths.values():
        assert Path(p).exists()


def test_limitations_mention_untested(tmp_path):
    audit = sample_audit()
    audit.requirement_results += [{"requirement_id": f"REQ-{i:03d}",
                                   "status": "NOT_TESTED", "sources": [],
                                   "notes": [], "finding_ids": []}
                                  for i in range(1, 10)]
    write_html(audit, tmp_path / "r2.html")
    assert "NOT_TESTED" in (tmp_path / "r2.html").read_text() or \
           "could not be tested" in (tmp_path / "r2.html").read_text()
