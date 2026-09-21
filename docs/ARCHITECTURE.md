# Architecture

## Data flow

```
source (github/local/zip)
   │  acquire_github / safe_extract_zip / acquire_local   [apps/projects/sources.py]
   ▼
isolated workspace  workdir/audits/<id>/source/
   │
   ▼  discover_project()                                   [apps/projects/discovery.py]
ProjectProfile (django version, db, drf, auth, deploy, deps, markers)
   │
   ▼  AuditPipeline.run_full()                             [apps/audits/pipeline.py]
12 jobs, each isolated (safe_run): discovery → requirements → sast → settings →
dependencies → endpoints → app_start → dast → security_tests → network →
correlation → report
   │
   ▼  every engine emits (Finding*, Evidence*)             [scanners/base.py]
   │     Evidence.polarity ∈ {vuln, ok, info} + confidence
   ▼
correlation engine                                         [scanners/correlation/engine.py]
  • internal checks (REQ-130..137 platform guarantees)
  • dedupe_findings(): cross-engine merge (same CWE + shared requirement or
    same source/file/line)
  • correlate_requirements(): status per requirement
  • compute_score(): transparent deductions
   │
   ▼  reports                                              [apps/reports/]
PDF (dependency-free writer), HTML, JSON, CSV
```

## Requirement status computation (apps/requirements_engine/engine.py)

```
MANUAL/NOT_AUTOMATABLE                       -> MANUAL_REVIEW
vuln evidence with Confirmed/High confidence -> FAIL
vuln evidence with weaker confidence         -> PARTIAL (spec 19: needs validation)
ok evidence  + FULLY_AUTOMATED               -> PASS
ok evidence  + PARTIALLY_AUTOMATED           -> PARTIAL
info evidence + PARTIALLY_AUTOMATED          -> PARTIAL (review input collected)
nothing executed                             -> NOT_TESTED (with reason:
                                                which scanner FAILED/SKIPPED)
```

## Deduplication keys

* SAST: `sast:<rule>:<file>:<line>`
* Settings: `config:<check>:<setting>`
* Dependencies: `dep:<rule>:<package>:<advisory>`
* Network: `net:<rule>:<host>:<port>`
* DAST: `dast:<rule>:<url>` · tests: `test:<id>:<url>`

Merge rule: same primary CWE AND (shared requirement across engines OR same
source+file+line). Merged findings keep worst severity, strongest confidence,
union of evidence/requirements/sources.

## Confidence model (spec 19)

Direct request-data flow into a sink → `Confirmed`. Indirect taint or
structural detection → rule default (`High`/`Medium`). Static-only or
context-dependent → `Potential`. Only Confirmed/High vuln evidence fails a
requirement.

## Persistence

`AuditStore` writes one JSON artifact per audit (`workdir/audits/<id>/audit.json`)
plus `reports/` and an index. The same object model maps 1:1 to the PostgreSQL
schema in `docs/schema.sql` for the multi-user deployment.

## Production deployment

`docker-compose.yml`: frontend, backend (FastAPI), worker, postgres, redis,
scanner (no network), network-scanner (NET_RAW only), zap. Scanner containers
run as non-root users with CPU/RAM/pids limits and scan timeouts.
