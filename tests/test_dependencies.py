"""Dependency scanner (spec 10): advisories, pinning, lockfiles."""
import textwrap

from apps.projects.discovery import discover_project, parse_requirements_txt
from scanners.base import AuditContext
from scanners.dependencies.scanner import DependencyScanner, _parse_pinned, load_advisories


def run(src):
    ctx = AuditContext(source_dir=src)
    ctx.profile = discover_project(src)
    return DependencyScanner().safe_run(ctx)


def test_advisory_db_loads():
    adv = load_advisories()
    assert "django" in adv and "pyyaml" in adv
    assert all("id" in a and "fixed" in a for entries in adv.values() for a in entries)


def test_pinned_version_detection():
    assert _parse_pinned("==4.2.1") == "4.2.1"
    assert _parse_pinned(">=4.2") is None
    assert _parse_pinned("") is None


def test_requirements_txt_parsing(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "Django==4.2.1\nrequests>=2\n# comment\n-r extra.txt\n")
    (tmp_path / "extra.txt").write_text("celery==5.3.1\n")
    deps = parse_requirements_txt((tmp_path / "requirements.txt").read_text(), tmp_path)
    names = [d["name"] for d in deps]
    assert "Django" in names and "celery" in names and "requests" in names


def test_known_cve_detected(vulnerable_app):
    r = run(vulnerable_app)
    titles = [f.title for f in r.findings]
    assert any("CVE-2024-45230" in t for t in titles)        # Django 4.2.1
    assert any("CVE-2020-14343" in t for t in titles)        # pyyaml 5.3.1
    assert any("CVE-2023-50447" in t for t in titles)        # Pillow 9.0.0


def test_fixed_version_not_flagged(tmp_path):
    (tmp_path / "requirements.txt").write_text("Django==4.2.16\n")
    r = run(str(tmp_path))
    cve = [f for f in r.findings if "CVE" in f.title]
    assert not cve, [f.title for f in cve]


def test_unpinned_dependency_flagged(vulnerable_app):
    r = run(vulnerable_app)
    assert any(f.title.startswith("Unpinned dependency: requests") for f in r.findings)


def test_pinned_evidence_ok(tmp_path):
    (tmp_path / "requirements.txt").write_text("Django==4.2.16\n")
    r = run(str(tmp_path))
    assert any(e.polarity == "ok" and e.rule_id == "DEP-PIN-001" for e in r.evidence)


def test_dangerous_package_flagged(tmp_path):
    (tmp_path / "requirements.txt").write_text("pycrypto==2.6.1\n")
    r = run(str(tmp_path))
    assert any("Dangerous/unmaintained" in f.title for f in r.findings)


def test_pyproject_dependencies(tmp_path):
    (tmp_path / "pyproject.toml").write_text(textwrap.dedent("""
        [project]
        name = "x"
        dependencies = ["Django==4.2.1", "requests==2.31.0"]
    """))
    r = run(str(tmp_path))
    assert any("CVE-2024-45230" in f.title for f in r.findings)


def test_poetry_lock_parsed(tmp_path):
    (tmp_path / "poetry.lock").write_text(textwrap.dedent("""
        [[package]]
        name = "django"
        version = "4.2.1"
    """))
    r = run(str(tmp_path))
    assert any("django" in f.title.lower() and "CVE-2024-45230" in f.title
               for f in r.findings)


def test_no_manifests_skipped(tmp_path):
    r = run(str(tmp_path))
    assert r.status == "SKIPPED"


def test_dependency_findings_mapped_to_requirements(vulnerable_app):
    r = run(vulnerable_app)
    for f in r.findings:
        assert set(f.requirement_ids) & {"REQ-059", "REQ-060", "REQ-061", "REQ-063"}


def test_advisory_reference_in_evidence(vulnerable_app):
    r = run(vulnerable_app)
    advs = [e.location.get("advisory") for e in r.evidence
            if e.rule_id == "DEP-CVE-001" and e.polarity == "vuln"]
    assert any(a and a.startswith("CVE-") for a in advs)
