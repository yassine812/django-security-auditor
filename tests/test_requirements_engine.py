"""Requirement status engine - never converts absence of findings into PASS."""
from apps.requirements_engine.engine import compute_status
from apps.requirements_engine.loader import load_requirements

REQS = {r.id: r for r in load_requirements()}


def ev(polarity, source="sast", reqs=("REQ-013",), rule="X-001"):
    return {"id": "EV-1", "source": source, "rule_id": rule, "polarity": polarity,
            "summary": "s", "location": {}, "requirement_ids": list(reqs)}


def test_manual_requirement_is_manual_review():
    res = compute_status(REQS["REQ-043"], [], {"sast": "SUCCESS"})
    assert res["status"] == "MANUAL_REVIEW"


def test_no_evidence_is_not_tested():
    res = compute_status(REQS["REQ-015"], [], {"settings": "SUCCESS"})
    assert res["status"] == "NOT_TESTED"


def test_vuln_evidence_is_fail():
    res = compute_status(REQS["REQ-013"], [ev("vuln")], {"sast": "SUCCESS"})
    assert res["status"] == "FAIL"


def test_vuln_beats_ok():
    res = compute_status(REQS["REQ-013"], [ev("ok"), ev("vuln")], {"sast": "SUCCESS"})
    assert res["status"] == "FAIL"


def test_ok_evidence_fully_automated_is_pass():
    res = compute_status(REQS["REQ-015"], [ev("ok", source="configuration")],
                         {"settings": "SUCCESS"})
    assert res["status"] == "PASS"


def test_ok_evidence_partial_automation_is_partial():
    res = compute_status(REQS["REQ-004"], [ev("ok", source="dast")], {"dast": "SUCCESS"})
    assert res["status"] == "PARTIAL"


def test_info_only_evidence_is_not_pass():
    # REQ-024 is PARTIALLY_AUTOMATED: informational evidence yields PARTIAL
    res = compute_status(REQS["REQ-024"], [ev("info", source="configuration")],
                         {"settings": "SUCCESS"})
    assert res["status"] == "PARTIAL"
    assert res["status"] != "PASS"


def test_medium_confidence_vuln_is_partial_not_fail():
    # spec 19: potential/medium-confidence detections need manual validation
    e = ev("vuln")
    e["confidence"] = "Medium"
    res = compute_status(REQS["REQ-013"], [e], {"sast": "SUCCESS"})
    assert res["status"] == "PARTIAL"


def test_confirmed_vuln_still_fails():
    e = ev("vuln")
    e["confidence"] = "Confirmed"
    res = compute_status(REQS["REQ-013"], [e], {"sast": "SUCCESS"})
    assert res["status"] == "FAIL"


def test_strong_vuln_overrides_weak():
    weak = ev("vuln")
    weak["confidence"] = "Low"
    strong = ev("vuln", rule="SECRET-001")
    strong["confidence"] = "Confirmed"
    res = compute_status(REQS["REQ-013"], [weak, strong], {"sast": "SUCCESS"})
    assert res["status"] == "FAIL"


def test_failed_scanner_explains_not_tested():
    res = compute_status(REQS["REQ-001"], [], {"dast": "FAILED"})
    assert res["status"] == "NOT_TESTED"
    assert any("FAILED" in n for n in res["notes"])


def test_not_applicable():
    res = compute_status(REQS["REQ-001"], [], {}, applicable=False)
    assert res["status"] == "NOT_APPLICABLE"


def test_evidence_ids_recorded():
    e = ev("vuln")
    res = compute_status(REQS["REQ-013"], [e], {"sast": "SUCCESS"})
    assert res["evidence_ids"] == ["EV-1"]


def test_sources_recorded():
    res = compute_status(REQS["REQ-013"], [ev("vuln", source="sast")], {"sast": "SUCCESS"})
    assert res["sources"] == ["sast"]


def test_spec_example_req13_fails_on_hardcoded_secret():
    # spec section 7: SAST detects SECRET_KEY/API_KEY/password -> FAIL
    evidence = [ev("vuln", rule="SECRET-001"), ev("vuln", rule="SECRET-002")]
    res = compute_status(REQS["REQ-013"], evidence, {"sast": "SUCCESS"})
    assert res["status"] == "FAIL"
