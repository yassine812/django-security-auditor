"""Audit orchestration pipeline (spec 1, 20).

Runs the full scan sequence as isolated jobs; a failing scanner degrades its
own step to FAILED/SKIPPED and dependent requirements become NOT_TESTED - it
never crashes the audit and never converts an unavailable test into PASS
(spec 36).
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from apps.audits.config import load_config
from apps.audits.models import Audit, AuditStore
from apps.audits.utils import mask_secrets
from apps.projects.discovery import discover_project
from apps.requirements_engine.loader import load_requirements
from scanners.base import AuditContext, Evidence, Finding
from scanners.configuration.django_settings import DjangoSettingsScanner
from scanners.correlation.engine import (compute_score, correlate_requirements,
                                         dedupe_findings, internal_checks)
from scanners.dast.endpoints import discover_endpoints
from scanners.dast.sandbox import start_application, stop_application
from scanners.dast.scanner import DASTScanner
from scanners.dependencies.scanner import DependencyScanner
from scanners.network.scanner import NetworkScanner
from scanners.sast.scanner import SASTScanner
from security_tests.framework import TestContext
from security_tests.tests import TestRunner

PIPELINE_STEPS = ["discovery", "requirements", "sast", "settings", "dependencies",
                  "endpoints", "app_start", "dast", "security_tests", "network",
                  "correlation", "report"]


class AuditPipeline:
    def __init__(self, store: AuditStore, config_path: str | None = None):
        self.store = store
        self.config_path = config_path
        self._log_listeners = []

    # ------------------------------------------------------------------
    def create_audit(self, project: dict, authorization_confirmed: bool = False,
                     retest_of: str | None = None) -> Audit:
        from apps.audits.models import new_audit_id
        config = load_config(self.config_path)
        audit = Audit(id=new_audit_id(), project=project, config=config,
                      authorization_confirmed=authorization_confirmed,
                      retest_of=retest_of)
        audit.log("INFO", f"Audit created for project '{project.get('name')}' "
                          f"(source: {project.get('source_type')})")
        self.store.save(audit)
        return audit

    # ------------------------------------------------------------------
    def run_full(self, audit: Audit) -> Audit:
        audit.status = "RUNNING"
        self.store.save(audit)
        ctx = AuditContext(
            source_dir=audit.project["path"],
            config=audit.config,
            authorization_confirmed=audit.authorization_confirmed,
            logger=lambda level, msg: audit.log(level, mask_secrets(msg)),
        )

        scanning = audit.config.get("scanning", {})

        # -- 1. project discovery ---------------------------------------
        self._job(audit, "discovery", lambda: self._step_discovery(audit, ctx))

        # -- 2. requirements initialization ------------------------------
        self._job(audit, "requirements", lambda: self._step_requirements(audit))

        # -- 3. SAST (pattern + AST) -------------------------------------
        if scanning.get("sast", True):
            self._job(audit, "sast", lambda: self._step_scanner(audit, ctx, SASTScanner()))
        else:
            audit.set_job("sast", "SKIPPED", "disabled in configuration")

        # -- 4. Django settings ------------------------------------------
        self._job(audit, "settings", lambda: self._step_scanner(audit, ctx,
                                                                 DjangoSettingsScanner()))

        # -- 5. dependencies ------------------------------------------------
        if scanning.get("dependencies", True):
            self._job(audit, "dependencies", lambda: self._step_scanner(audit, ctx,
                                                                        DependencyScanner()))
        else:
            audit.set_job("dependencies", "SKIPPED", "disabled in configuration")

        # -- 6. endpoint discovery -------------------------------------------
        self._job(audit, "endpoints", lambda: self._step_endpoints(audit, ctx))

        # -- 7. application startup (sandbox) -----------------------------------
        startup = None
        if ctx.dast_allowed() and scanning.get("dast", True):
            self._job(audit, "app_start", lambda: None)  # placeholder status
            audit.set_job("app_start", "RUNNING")
            audit.log("INFO", "Starting isolated application instance for DAST")
            startup = start_application(ctx.source_dir, audit.config,
                                        audit.project.get("source_type", "local"))
            if startup.started:
                ctx.base_url = startup.base_url
                audit.set_job("app_start", "SUCCESS")
                audit.log("INFO", f"Application started at {startup.base_url} "
                                  f"({startup.method})")
            else:
                audit.set_job("app_start", "FAILED", startup.reason)
                audit.log("WARN", f"Application could not start: {startup.reason[:300]}")
        else:
            reason = ("authorization not confirmed" if not audit.authorization_confirmed
                      else "DAST disabled in configuration")
            audit.set_job("app_start", "SKIPPED", reason)

        # -- 8. DAST -------------------------------------------------------------
        if scanning.get("dast", True):
            self._job(audit, "dast", lambda: self._step_scanner(audit, ctx, DASTScanner()))
        else:
            audit.set_job("dast", "SKIPPED", "disabled in configuration")

        # -- 9. automated security tests -------------------------------------------
        if scanning.get("security_tests", True) or scanning.get("dast", True):
            self._job(audit, "security_tests", lambda: self._step_security_tests(audit, ctx))
        else:
            audit.set_job("security_tests", "SKIPPED", "disabled in configuration")

        # -- 10. network ------------------------------------------------------------
        if scanning.get("network", True):
            self._job(audit, "network", lambda: self._step_scanner(audit, ctx, NetworkScanner()))
        else:
            audit.set_job("network", "SKIPPED", "disabled in configuration")

        # -- cleanup sandbox ---------------------------------------------------------
        if startup is not None:
            stop_application(startup)

        # -- 11. correlation -----------------------------------------------------------
        self._job(audit, "correlation", lambda: self._step_correlation(audit))

        # -- 12. report ------------------------------------------------------------------
        self._job(audit, "report", lambda: self._step_report(audit))

        audit.status = "COMPLETE"
        audit.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        audit.log("INFO", "Audit complete")
        self.store.save(audit)
        return audit

    # ------------------------------------------------------------------
    def _job(self, audit: Audit, name: str, fn):
        audit.set_job(name, "RUNNING")
        self.store.save(audit)
        started = time.time()
        try:
            fn()
            job = audit.job(name)
            if job and job["status"] == "RUNNING":
                audit.set_job(name, "SUCCESS")
        except Exception as exc:  # noqa: BLE001 - isolation boundary
            audit.set_job(name, "FAILED", str(exc)[:500])
            audit.log("ERROR", f"step {name} failed: {exc}")
        finally:
            audit.log("INFO", f"step {name} finished in {time.time() - started:.1f}s")
            self.store.save(audit)

    # ------------------------------------------------------------------
    def _step_discovery(self, audit: Audit, ctx: AuditContext):
        profile = discover_project(ctx.source_dir)
        audit.profile = profile
        ctx.profile = profile
        audit.project["profile"] = {
            "is_django": profile["is_django"],
            "django_version_hint": profile.get("django_version_hint"),
            "databases": profile.get("databases"),
            "api": profile.get("api"),
        }
        if not profile["is_django"]:
            audit.log("WARN", "Django was not detected - audit continues but "
                              "Django-specific checks may be limited")
        audit.log("INFO", f"Project discovered: django={profile['is_django']}, "
                          f"deps={len(profile['dependencies'])}, "
                          f"py_files={profile['stats']['python_files']}")

    def _step_requirements(self, audit: Audit):
        reqs = load_requirements()
        audit.log("INFO", f"Loaded {len(reqs)} security requirements")
        audit.requirement_results = []   # filled by correlation
        return reqs

    def _step_scanner(self, audit: Audit, ctx: AuditContext, scanner):
        result = scanner.safe_run(ctx)
        audit.log("INFO", f"{scanner.name}: status={result.status}, "
                          f"findings={len(result.findings)}, evidence={len(result.evidence)}")
        if result.error:
            audit.set_job(scanner.name if scanner.name != "settings" else "settings",
                          result.status, result.error)
        audit.evidence += [e.to_dict() for e in result.evidence]
        audit.findings += [f.to_dict() for f in result.findings]
        if scanner.name == "sast":
            audit.sast_data = result.data
        elif scanner.name == "settings":
            audit.settings_values = result.data.get("settings", {})
        elif scanner.name == "dependencies":
            audit.dependencies_report = result.data
        elif scanner.name == "network":
            audit.network_report = result.data
        elif scanner.name == "dast":
            audit.dast_report = result.data
        if result.status == "FAILED":
            audit.set_job(scanner.name, "FAILED", result.error or "scanner error")
        elif result.status == "SKIPPED":
            audit.set_job(scanner.name, "SKIPPED", result.error)

    def _step_endpoints(self, audit: Audit, ctx: AuditContext):
        eps = discover_endpoints(ctx.source_dir, audit.profile.get("urls_files"))
        audit.endpoints = eps
        ctx.endpoints = eps
        audit.log("INFO", f"Endpoint discovery: {len(eps)} endpoints inventoried")

    def _step_security_tests(self, audit: Audit, ctx: AuditContext):
        tctx = TestContext(base_url=ctx.base_url, endpoints=audit.endpoints,
                           accounts=(audit.config.get("accounts") or {}),
                           profile=audit.profile)
        executions, evidence, findings = TestRunner().run_all(tctx)
        audit.test_executions = executions
        audit.evidence += [e.to_dict() for e in evidence]
        audit.findings += [f.to_dict() for f in findings]
        passed = sum(1 for e in executions if e["status"] == "PASS")
        failed = sum(1 for e in executions if e["status"] == "FAIL")
        not_tested = sum(1 for e in executions if e["status"] == "NOT_TESTED")
        audit.log("INFO", f"Security tests: {passed} passed, {failed} failed, "
                          f"{not_tested} not testable")

    def _step_correlation(self, audit: Audit):
        requirements = load_requirements()
        evidence = [Evidence.from_dict(e) for e in audit.evidence]
        findings = [Finding.from_dict(f) for f in audit.findings]

        # internal platform checks add evidence for REQ-130..137
        evidence += internal_checks(audit, findings, audit.sast_data or {})

        deduped = dedupe_findings(findings)
        audit.log("INFO", f"Deduplication: {len(findings)} raw findings -> "
                          f"{len(deduped)} unique findings")

        job_states = {j["name"]: j["status"] for j in audit.jobs}
        results = correlate_requirements(requirements, evidence, job_states)
        audit.requirement_results = results
        audit.findings = [f.to_dict() for f in deduped]
        audit.evidence = [e.to_dict() for e in evidence]

        # link findings -> requirement results (cross refs for the UI/report)
        req_findings = {}
        for f in deduped:
            for rid in f.requirement_ids:
                req_findings.setdefault(rid, []).append(f.id)
        for r in audit.requirement_results:
            r["finding_ids"] = req_findings.get(r["requirement_id"], [])

        audit.score = compute_score(deduped, results, requirements)
        from collections import Counter
        counts = Counter(r["status"] for r in results)
        audit.log("INFO", f"Requirement statuses: {dict(counts)}")

    def _step_report(self, audit: Audit):
        from apps.reports.generator import generate_all_reports
        paths = generate_all_reports(self.store, audit)
        audit.log("INFO", f"Reports generated: {', '.join(paths.keys())}")
        audit.report_paths = paths
