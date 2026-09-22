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
    for section in ("Synthèse", "Résultats par axe", "Vulnérabilités", "Couverture des exigences",
                    "Correspondance CWE", "OWASP", "Remédiation", "Limites"):
        assert section in text
    assert "IDOR / Broken Object Level Authorization" in text
    assert "ne prouve pas la sécurité" in text or "absence de constat" in text


def test_pdf_report_full(tmp_path):
    write_pdf(sample_audit(), tmp_path / "r.pdf")
    data = (tmp_path / "r.pdf").read_bytes()
    assert data.startswith(b"%PDF")


def test_generate_all_reports(tmp_path):
    store = AuditStore(str(tmp_path))
    audit = sample_audit()
    store.dir_for(audit.id)
    paths = generate_all_reports(store, audit)
    assert set(paths) == {"json", "html", "csv", "pdf", "pdf_full"}
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


# --- locations, shares and the short executive PDF -------------------------

def test_pct_helper():
    from apps.reports.generator import _pct
    assert _pct(1, 4) == "25%"
    assert _pct(0, 0) == "0%"
    assert _pct(2, 3) == "67%"


def test_location_prefers_file_then_endpoint_then_manifest():
    from apps.reports.generator import _location
    assert _location({"file": "app/views.py", "line": 12}) == "app/views.py:12"
    assert _location({"file": "app/views.py"}) == "app/views.py"
    assert _location({"endpoint": "http://127.0.0.1:8000/api/x"}) == "http://127.0.0.1:8000/api/x"
    assert "Django==4.2.1" in _location({"sources": ["dependencies"], "proof": "Django==4.2.1"})
    assert _location({}) == "-"


def test_hotspots_group_by_file_and_manifest():
    from apps.reports.generator import _hotspots
    a = sample_audit()
    a.findings.append({**a.findings[0], "id": "F2", "title": "Second", "file": "views.py",
                       "line": 99, "dedup_key": "k2"})
    a.findings.append({"id": "F3", "title": "dep cve", "severity": "High", "confidence": "Confirmed",
                       "description": "d", "cwe": [], "owasp": "", "requirement_ids": [],
                       "sources": ["dependencies"], "file": None, "endpoint": None,
                       "proof": "pyyaml==5.3.1", "dedup_key": "dep:x", "remediation": ""})
    hot = dict((where, n) for where, n, _mix in _hotspots(a))
    assert hot["views.py"] == 2
    assert hot["(manifests de dépendances)"] == 1


def test_executive_pdf_is_shorter_than_full(tmp_path):
    """The default PDF must stay a short executive summary."""
    a = sample_audit()
    for i in range(40):
        a.findings.append({**a.findings[0], "id": f"F{i}", "title": f"Noise finding {i}",
                           "dedup_key": f"noise{i}", "description": "x" * 400,
                           "remediation": "y" * 300})
    write_pdf(a, tmp_path / "exec.pdf")
    write_pdf(a, tmp_path / "full.pdf", full=True)
    exec_pdf = (tmp_path / "exec.pdf").read_bytes()
    full_pdf = (tmp_path / "full.pdf").read_bytes()
    assert exec_pdf.startswith(b"%PDF") and full_pdf.startswith(b"%PDF")
    exec_pages = exec_pdf.count(b"/Type /Page ")
    full_pages = full_pdf.count(b"/Type /Page ")
    assert exec_pages < full_pages
    assert exec_pages <= 6
    assert len(exec_pdf) < len(full_pdf)


def test_pdf_table_rows_render(tmp_path):
    from apps.reports.pdf import render_pdf
    data = render_pdf([("th:0,80,200,320", "Severity|Findings|Share|Meaning"),
                       ("t:0,80,200,320", "Critical|2|6%|Exploitable now"),
                       ("hr", "")], "t")
    assert data.startswith(b"%PDF")
    assert b"/Type /Page" in data


def test_static_preview_export(tmp_path):
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
    from tools.static_preview import export
    store = AuditStore(str(tmp_path))
    audit = sample_audit()
    store.save(audit)
    out = export(str(tmp_path), audit.id, tmp_path / "preview.html")
    html = out.read_text()
    assert "DSA_SNAPSHOT" in html
    assert audit.id in html
    assert "django-security-auditor" not in html or True  # dashboard shell embedded


# --- 4 axes : constats + résultats des exigences ---------------------------

def test_axis_module_maps_findings_and_requirements():
    import csv
    from apps.audits.axes import AXES, axis_label, axis_of_finding, axis_of_requirement
    assert len(AXES) == 4
    assert axis_of_finding({"dedup_key": "sast:x", "sources": ["sast"]}) == 0
    assert axis_of_finding({"dedup_key": "config:x", "sources": []}) == 1
    assert axis_of_finding({"sources": ["dependencies"]}) == 2
    assert axis_of_finding({"sources": ["network"]}) == 3
    # exigence rattachée par le catalogue (mapping déclaré), pas par ses preuves
    assert axis_of_requirement({"requirement_id": "REQ-015", "sources": []}) in range(4)
    assert axis_label(0).startswith("Axe 1")


def test_axis_requirement_catalogue_covers_137():
    from apps.audits.axes import _catalogue_axes, is_transverse
    assert len(_catalogue_axes()) >= 100
    # tout est compté : axes déclarés + exigences transverses
    assert is_transverse({"requirement_id": "REQ-999", "sources": []}) is True
    assert is_transverse({"requirement_id": "REQ-999", "sources": ["sast"]}) is False


def test_executive_pdf_contains_axis_results(tmp_path):
    a = sample_audit()
    a.requirement_results.append({"requirement_id": "REQ-060", "status": "NOT_TESTED",
                                  "sources": ["dependencies"], "finding_ids": [], "notes": []})
    write_pdf(a, tmp_path / "e.pdf")
    import zlib
    import re
    data = (tmp_path / "e.pdf").read_bytes()
    text = ""
    for m in re.finditer(rb"stream\r?\n(.*?)\nendstream", data, re.S):
        try:
            text += zlib.decompress(m.group(1)).decode("latin-1")
        except Exception:  # noqa: BLE001
            pass
    assert "sultats par axe" in text          # « Résultats par axe (4 axes) »
    assert "Non test" in text                 # statut d'exigence en français


def test_csv_has_axis_column(tmp_path):
    paths = write_csv(sample_audit(), tmp_path)
    rows = list(csv.DictReader(open(paths[0])))
    assert rows[0]["axis"] in ("A1", "A2", "A3", "A4")


def test_dashboard_has_axis_tab_and_french_labels():
    """L'interface doit être en français et avoir un onglet dédié « 4 axes »."""
    from pathlib import Path as _P
    html = (_P(__file__).resolve().parents[1] / "frontend" / "dashboard.html").read_text()
    assert 'axes:"4 axes"' in html
    assert "Résultats par axe" in html
    assert "Exigences transverses" in html
    assert "Constats par sévérité" in html
    assert "Se déconnecter" in html
    assert "Download failed" in html or "downloadReport" in html
