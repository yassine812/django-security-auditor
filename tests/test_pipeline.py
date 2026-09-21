"""End-to-end pipeline tests (spec 20, 36, 45)."""
import yaml

import pytest

from apps.audits.models import AuditStore
from apps.audits.pipeline import AuditPipeline


@pytest.fixture()
def fast_config(tmp_path):
    cfg = tmp_path / "security-audit.yml"
    cfg.write_text(yaml.safe_dump({
        "scanning": {"sast": True, "dependencies": True, "network": True,
                     "dast": False, "requirements": True, "security_tests": True},
        "network": {"authorized_targets": ["127.0.0.1"], "scan_ports": [1]},
    }))
    return str(cfg)


def run_audit(workdir, source, fast_config, authorized=True):
    store = AuditStore(workdir)
    pipeline = AuditPipeline(store, fast_config)
    project = {"name": "fixture", "source_type": "local", "path": source}
    audit = pipeline.create_audit(project, authorization_confirmed=authorized)
    return pipeline.run_full(audit), store


def test_full_pipeline_completes(workdir, vulnerable_app, fast_config):
    audit, _ = run_audit(workdir, vulnerable_app, fast_config)
    assert audit.status == "COMPLETE"
    jobs = {j["name"]: j["status"] for j in audit.jobs}
    assert jobs["discovery"] == "SUCCESS"
    assert jobs["sast"] == "SUCCESS"
    assert jobs["settings"] == "SUCCESS"
    assert jobs["dependencies"] == "SUCCESS"
    assert jobs["correlation"] == "SUCCESS"
    assert jobs["report"] == "SUCCESS"


def test_137_requirement_results(workdir, vulnerable_app, fast_config):
    audit, _ = run_audit(workdir, vulnerable_app, fast_config)
    assert len(audit.requirement_results) == 137


def test_vulnerable_app_fails_req13(workdir, vulnerable_app, fast_config):
    audit, _ = run_audit(workdir, vulnerable_app, fast_config)
    by_id = {r["requirement_id"]: r for r in audit.requirement_results}
    assert by_id["REQ-013"]["status"] == "FAIL"
    assert by_id["REQ-015"]["status"] == "FAIL"     # DEBUG=True
    assert by_id["REQ-016"]["status"] == "FAIL"     # ALLOWED_HOSTS *
    assert by_id["REQ-029"]["status"] == "FAIL"     # eval/exec
    assert by_id["REQ-009"]["status"] == "FAIL"     # CSRF middleware missing


def test_secure_app_passes_fully_automated_settings(workdir, secure_app, fast_config):
    audit, _ = run_audit(workdir, secure_app, fast_config)
    by_id = {r["requirement_id"]: r for r in audit.requirement_results}
    assert by_id["REQ-015"]["status"] == "PASS"
    assert by_id["REQ-016"]["status"] == "PASS"
    assert by_id["REQ-020"]["status"] == "PASS"
    # CSRF control present but requirement is only partially automatable
    assert by_id["REQ-009"]["status"] in ("PASS", "PARTIAL")
    assert by_id["REQ-013"]["status"] != "FAIL"


def test_dast_unavailable_never_becomes_pass(workdir, vulnerable_app, fast_config):
    audit, _ = run_audit(workdir, vulnerable_app, fast_config)
    jobs = {j["name"]: j["status"] for j in audit.jobs}
    assert jobs["dast"] == "SKIPPED"
    by_id = {r["requirement_id"]: r for r in audit.requirement_results}
    # REQ-136 depends on a running DAST target; must not be PASS
    assert by_id["REQ-136"]["status"] in ("NOT_TESTED", "MANUAL_REVIEW")


def test_manual_requirements_flagged(workdir, vulnerable_app, fast_config):
    audit, _ = run_audit(workdir, vulnerable_app, fast_config)
    by_id = {r["requirement_id"]: r for r in audit.requirement_results}
    for rid in ("REQ-043", "REQ-026", "REQ-055"):
        assert by_id[rid]["status"] == "MANUAL_REVIEW"


def test_reports_generated(workdir, vulnerable_app, fast_config):
    audit, store = run_audit(workdir, vulnerable_app, fast_config)
    for kind in ("json", "html", "csv", "pdf"):
        assert audit.report_paths.get(kind)
    from pathlib import Path
    assert Path(audit.report_paths["pdf"]).read_bytes().startswith(b"%PDF")


def test_findings_deduplicated(workdir, vulnerable_app, fast_config):
    audit, _ = run_audit(workdir, vulnerable_app, fast_config)
    keys = [f["dedup_key"] for f in audit.findings]
    assert len(keys) == len(set(keys))


def test_store_roundtrip(workdir, vulnerable_app, fast_config):
    audit, store = run_audit(workdir, vulnerable_app, fast_config)
    loaded = store.load(audit.id)
    assert loaded.id == audit.id
    assert len(loaded.findings) == len(audit.findings)


def test_audit_persisted_in_index(workdir, vulnerable_app, fast_config):
    audit, store = run_audit(workdir, vulnerable_app, fast_config)
    assert any(i["id"] == audit.id for i in store.list_audits())


def test_score_and_counts_present(workdir, vulnerable_app, fast_config):
    audit, _ = run_audit(workdir, vulnerable_app, fast_config)
    assert audit.score["score"] >= 0
    assert sum(audit.score["requirements_by_status"].values()) == 137
