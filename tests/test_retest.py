"""Retest comparison (spec 29)."""
from apps.audits.models import Audit
from apps.audits.retest import compare_audits, run_retest
from apps.audits.models import AuditStore
from apps.audits.pipeline import AuditPipeline
import yaml


def audit_with_findings(fingerprints):
    a = Audit(id="x", project={"name": "p", "source_type": "local", "path": "/p"})
    for i, fp in enumerate(fingerprints):
        a.findings.append({"id": f"F{i}", "title": f"finding {i}", "severity": "High",
                           "dedup_key": fp, "cwe": ["CWE-89"], "sources": ["sast"]})
    return a


def test_fixed_still_new_classification():
    before = audit_with_findings(["k1", "k2"])
    after = audit_with_findings(["k2", "k3"])
    cmp_ = compare_audits(before, after)
    assert [f["fingerprint"] for f in cmp_["fixed"]] == ["k1"]
    assert [f["fingerprint"] for f in cmp_["still_present"]] == ["k2"]
    assert [f["fingerprint"] for f in cmp_["new"]] == ["k3"]
    assert cmp_["summary"] == {"fixed": 1, "still_present": 1, "new": 1}


def test_requirement_status_changes_tracked():
    before = audit_with_findings([])
    after = audit_with_findings([])
    before.requirement_results = [{"requirement_id": "REQ-015", "status": "FAIL"}]
    after.requirement_results = [{"requirement_id": "REQ-015", "status": "PASS"}]
    cmp_ = compare_audits(before, after)
    assert cmp_["requirement_changes"] == [
        {"requirement_id": "REQ-015", "before": "FAIL", "after": "PASS"}]


def test_retest_status_marked_on_findings():
    before = audit_with_findings(["k1"])
    after = audit_with_findings(["k1"])
    compare_audits(before, after)
    assert after.findings[0]["retest_status"] == "STILL_PRESENT"


def test_run_retest_end_to_end(workdir, vulnerable_app, secure_app):
    cfg_path = None
    import tempfile, os
    cfg = os.path.join(workdir, "cfg.yml")
    os.makedirs(workdir, exist_ok=True)
    with open(cfg, "w") as fh:
        yaml.safe_dump({"scanning": {"dast": False},
                        "network": {"authorized_targets": ["127.0.0.1"],
                                    "scan_ports": [1]}}, fh)
    store = AuditStore(workdir)
    pipeline = AuditPipeline(store, cfg)
    first = pipeline.create_audit({"name": "app", "source_type": "local",
                                   "path": vulnerable_app},
                                  authorization_confirmed=True)
    first = pipeline.run_full(first)
    retested = run_retest(store, first.id, secure_app, authorization_confirmed=True,
                          config_path=cfg)
    assert retested.retest_of == first.id
    assert retested.comparison["summary"]["fixed"] > 0
    assert retested.comparison["summary"]["still_present"] >= 0
