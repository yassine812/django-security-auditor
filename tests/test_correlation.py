"""Correlation, deduplication and scoring (spec 16-18, 28)."""
from apps.audits.models import Audit
from apps.requirements_engine.loader import load_requirements
from scanners.base import Evidence, Finding
from scanners.correlation.engine import (compute_score, correlate_requirements,
                                         dedupe_findings, internal_checks)

REQS = load_requirements()


def finding(sev="High", cwe=("CWE-639",), reqs=("REQ-004",), sources=("sast",),
            dedup="k", file="views.py", endpoint=None):
    return Finding(title="t", description="d", severity=sev, confidence="High",
                   category="c", cwe=list(cwe), owasp="A01:2021",
                   requirement_ids=list(reqs), sources=list(sources),
                   evidence_ids=["EV-1"], file=file, endpoint=endpoint,
                   remediation="fix it", dedup_key=dedup)


def ev(rids, polarity="vuln", source="sast"):
    return Evidence(source=source, rule_id="R", polarity=polarity, summary="s",
                    requirement_ids=list(rids))


# ---- deduplication -----------------------------------------------------

def test_cross_engine_dedup_merges():
    sast = finding(sources=("sast",), file="views.py", dedup="sast:AUTHZ:views.py:42")
    dast = finding(sources=("dast",), file=None, endpoint="/api/documents/26",
                   dedup="dast:IDOR:/api/documents/26")
    merged = dedupe_findings([sast, dast])
    assert len(merged) == 1
    assert set(merged[0].sources) == {"sast", "dast"}
    assert merged[0].file == "views.py"
    assert merged[0].endpoint == "/api/documents/26"


def test_same_engine_same_line_same_cwe_merges():
    a = finding(sources=("sast",), dedup="sast:SECRET-002:f:1", file="views.py")
    a.line = 12
    b = finding(sources=("sast",), dedup="sast:SECRET-006:f:1", file="views.py")
    b.line = 12
    assert len(dedupe_findings([a, b])) == 1


def test_different_cwe_not_merged():
    a = finding(cwe=("CWE-89",), dedup="a")
    b = finding(cwe=("CWE-79",), dedup="b")
    assert len(dedupe_findings([a, b])) == 2


def test_merged_severity_is_worst():
    a = finding(sev="Medium", dedup="x", sources=("sast",))
    b = finding(sev="Critical", dedup="y", sources=("dast",), file=None)
    merged = dedupe_findings([a, b])
    assert merged[0].severity == "Critical"


def test_merged_confidence_is_strongest():
    a = finding(dedup="x", sources=("sast",))
    a.confidence = "Potential"
    b = finding(dedup="y", sources=("dast",), file=None)
    b.confidence = "Confirmed"
    assert dedupe_findings([a, b])[0].confidence == "Confirmed"


def test_evidence_ids_unioned():
    a = finding(dedup="x", sources=("sast",))
    b = finding(dedup="y", sources=("dast",), file=None)
    b.evidence_ids = ["EV-2"]
    merged = dedupe_findings([a, b])
    assert set(merged[0].evidence_ids) == {"EV-1", "EV-2"}


# ---- requirement correlation ---------------------------------------------

def test_correlate_produces_137_results():
    results = correlate_requirements(REQS, [], {"sast": "SUCCESS"})
    assert len(results) == 137


def test_fail_status_from_vuln_evidence():
    results = correlate_requirements(REQS, [ev(["REQ-013"])], {"sast": "SUCCESS"})
    by_id = {r["requirement_id"]: r for r in results}
    assert by_id["REQ-013"]["status"] == "FAIL"


def test_pass_requires_ok_evidence():
    results = correlate_requirements(REQS, [ev(["REQ-015"], "ok", "configuration")],
                                     {"settings": "SUCCESS"})
    by_id = {r["requirement_id"]: r for r in results}
    assert by_id["REQ-015"]["status"] == "PASS"
    # an untouched requirement stays NOT_TESTED
    assert by_id["REQ-030"]["status"] == "NOT_TESTED"


# ---- internal checks --------------------------------------------------------

def test_internal_checks_pass_on_well_formed_audit():
    audit = Audit(id="a", project={"source_type": "local", "path": "/x", "name": "x",
                                   "commit_sha": "abc123", "branch": "main",
                                   "repo_url": None})
    f = finding()
    evs = internal_checks(audit, [f], {"files_scanned": 10})
    pol = {e.requirement_ids[0]: e.polarity for e in evs if e.polarity in ("ok", "vuln")}
    for rid in ("REQ-130", "REQ-131", "REQ-132", "REQ-133", "REQ-134", "REQ-135", "REQ-137"):
        assert pol.get(rid) == "ok", rid


def test_internal_check_flags_finding_without_evidence():
    audit = Audit(id="a", project={"source_type": "local", "path": "/x", "name": "x"})
    f = finding()
    f.evidence_ids = []
    evs = internal_checks(audit, [f], {})
    assert any(e.polarity == "vuln" and "REQ-130" in e.requirement_ids for e in evs)


# ---- score ----------------------------------------------------------------

def test_score_deducts_per_severity():
    findings = [finding(sev="Critical", dedup="1"), finding(sev="Low", dedup="2",
                                                            file="x.py")]
    results = correlate_requirements(REQS, [], {})
    score = compute_score(findings, results, REQS)
    assert score["score"] == 100 - 12 - 0.5
    assert score["findings_by_severity"]["Critical"] == 1


def test_score_never_negative():
    findings = [finding(sev="Critical", dedup=str(i)) for i in range(30)]
    score = compute_score(findings, [], REQS)
    assert score["score"] == 0


def test_score_disclaimer_present():
    score = compute_score([], [], REQS)
    assert "authoritative" in score["disclaimer"]
