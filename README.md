# Django Security Auditor

**Automated Django Security Audit Platform** — requirements-driven security
auditing against **137 Django security requirements**, combining SAST (regex +
AST + taint), dependency analysis, Django settings analysis, authorized
network scanning, DAST, automated authorization/security tests, evidence
correlation, deduplication, scoring, PDF/HTML/JSON/CSV reporting and retesting.

> **Honesty principle.** Absence of findings is never treated as proof of
> security. Every requirement gets an explicit status — `PASS`, `FAIL`,
> `PARTIAL`, `NOT_TESTED`, `NOT_APPLICABLE`, `MANUAL_REVIEW` — and a scanner
> that could not run turns its requirements into `NOT_TESTED`, never `PASS`.

---

## Quickstart

```bash
# from the repository root (no install needed)
./security-audit full ./my-django-project --yes

# or installed:
pip install -e ".[api]"
security-audit full ./my-django-project
```

Other entry points (spec §31):

```bash
security-audit github https://github.com/org/repo --branch main      # GitHub input
security-audit zip ./project.zip                                     # archive input
security-audit sast ./project                                        # SAST only
security-audit deps ./project                                        # dependencies only
security-audit requirements ./project                                # static req eval
security-audit network 127.0.0.1 --yes                               # authorized port scan
security-audit dast http://127.0.0.1:8000 --yes                      # DAST vs live app
security-audit report AUDIT_ID                                       # regenerate reports
security-audit retest AUDIT_ID ./fixed-project --yes                 # before/after compare
security-audit list | show AUDIT_ID
security-audit init                                                  # security-audit.yml
security-audit serve --host 127.0.0.1 --port 8300                    # API + dashboard
```

`--yes` stands for the mandatory authorization confirmation:

> *"I confirm that I am authorized to security-test this application and its
> infrastructure."*

Without confirmation, network and DAST steps are **skipped** (never assumed).

---

## What a full audit does

```
Create Audit → Choose GitHub / Local / ZIP
  → Project discovery (Django version, DB, DRF, auth, deployment, deps)
  → Requirements initialization (137 requirements from YAML)
  → SAST (regex patterns + Python AST + request-data taint tracking)
  → Django settings analysis (static AST parsing, never imports project code)
  → Dependency scan (embedded advisory DB + pinning + freshness)
  → Endpoint discovery (urls.py, DRF routers, include() resolution)
  → Isolated application start (Docker Compose → runserver fallback, loopback only)
  → DAST (headers, info exposure, debug pages, XSS/SQLi/traversal/redirect probes, ZAP hook)
  → Automated security tests (auth bypass, horizontal/vertical escalation, IDOR, CSRF, rate limits…)
  → Authorized network scan (nmap -sV if present, pure-Python fallback)
  → Correlation → deduplication → status computation → scoring
  → Reports (PDF / HTML / JSON / CSV) → retest comparison
```

Each pipeline job carries `QUEUED / RUNNING / SUCCESS / FAILED / SKIPPED`;
a failed scanner degrades only itself (e.g. *DAST: NOT COMPLETED — application
could not start → dependent requirements NOT_TESTED*).

---

## The 137 requirements

Defined as **data**, not code, in
[`requirements/django_137_requirements.yml`](requirements/django_137_requirements.yml),
generated from [`tools/reqdata_part1.py`](tools/reqdata_part1.py) /
[`tools/reqdata_part2.py`](tools/reqdata_part2.py):

```bash
python tools/generate_requirements.py   # validates + regenerates YAML
```

Every requirement carries `id, name, description, category, severity,
verification_method, automation_level, scanner_mapping, cwe, owasp,
test_definition, remediation`. Requirement→scanner wiring lives in
[`rules/requirement_mapping.yml`](rules/requirement_mapping.yml).

**Automation levels (spec §42)** are explicit and honest:

| level | meaning | example |
|---|---|---|
| `FULLY_AUTOMATED` | executed checks can PASS it | REQ-015 DEBUG disabled |
| `PARTIALLY_AUTOMATED` | automation finds violations; clean ≠ proven | REQ-004 cross-user access |
| `MANUAL` | requires human review | REQ-043 DB least privilege |
| `NOT_AUTOMATABLE` | process requirement | — |

Adding a requirement = one entry in the data tables + regenerate.

---

## Security engines

| engine | module | techniques |
|---|---|---|
| SAST | `scanners/sast/` | 40+ rules; regex layer (templates/secrets) + Python **AST** (sinks, imports resolution, intra-function **taint tracking**). Confidence model: direct request data → `Confirmed`, indirect → rule default (spec §19). Secrets always masked in evidence. |
| Settings | `scanners/configuration/` | AST parsing of every settings module (prod overrides base), ~25 checks (DEBUG, SECRET_KEY, cookies, HSTS, CORS, CSRF, middleware, DRF auth/perm/throttle/pagination, DB creds, hashers, validators…). |
| Dependencies | `scanners/dependencies/` | requirements.txt (+includes), pyproject.toml, Pipfile, poetry.lock; embedded advisory DB (`rules/advisories.yml`) + pinning + freshness checks. pip-audit/safety pluggable. |
| Network | `scanners/network/` | `nmap -sV` when available, pure-Python TCP+banner fallback. Authorization-gated: loopback/private defaults; public targets need `allow_external_targets: true` **and** an explicit allowlist entry. |
| DAST | `scanners/dast/` | sandboxed app start (Docker preferred, loopback `runserver` fallback, GitHub sources container-only), endpoint probes for XSS reflection, SQL error disclosure, traversal, open redirect, sensitive files (.env/.git), debug pages, admin/docs exposure, cookie flags, throttling. Optional **OWASP ZAP** via `dast.zap_api_url`. |
| Security tests | `security_tests/` | `SecurityTest` framework: AUTH-001 unauthenticated access, AUTHZ-V/H vertical/horizontal escalation, IDOR-001 (two-account comparison), XSS/SQLI/SSRF/traversal/redirect/CSRF/rate-limit probes, each with explicit *expected vs actual* results. |
| Correlation | `scanners/correlation/` | evidence→requirement status computation, cross-engine **deduplication** (same CWE + shared requirement/location merged into one finding), internal platform checks (REQ-130…137), transparent score. |

---

## Authentication & DAST test accounts

Configure test accounts in `security-audit.yml` for authenticated DAST and
horizontal/vertical escalation tests:

```yaml
accounts:
  admin:  {username: admin@example.com, password: "...", login_url: /admin/login/}
  user:   {username: user@example.com,  password: "..."}
  user_a: {username: a@example.com,     password: "..."}
  user_b: {username: b@example.com,     password: "..."}
```

Without accounts, the corresponding tests report `NOT_TESTED` — never a fake
PASS.

---

## Reports & retesting

Every audit produces `reports/report.{pdf,html,json}` + `findings.csv` /
`requirements.csv`. The PDF/HTML reports contain: executive summary, project
information, scan environment, requirements coverage & failures, SAST /
dependency / network / DAST results, vulnerabilities with evidence, CWE &
OWASP mapping, remediation, retest results and **limitations**.

`security-audit retest AUDIT_ID ./fixed-project` re-runs everything and classifies
each previous finding as **Fixed / Still present / New / Regressed**, plus
requirement status deltas.

---

## Repository layout

```
django-security-auditor/
├── apps/                    # API (FastAPI), audits, projects, requirements_engine,
│   │                        # findings, reports, users (auth/RBAC)
│   ├── api/server.py        # REST API + dashboard serving
│   ├── audits/pipeline.py   # orchestration (12 isolated jobs)
│   └── ...
├── scanners/
│   ├── sast/                # rules, regex patterns, AST analyzer, taint, scanner
│   ├── dast/                # sandbox, endpoint discovery, DAST scanner, http client
│   ├── network/             # authorized port/service scanning
│   ├── configuration/       # Django settings scanner
│   ├── dependencies/        # advisory DB + manifest scanners
│   └── correlation/         # status matrix, dedup, score
├── security_tests/          # automated security test framework + tests
├── worker/                  # job queue (Celery/RQ-swappable)
├── frontend/dashboard.html  # single-page dashboard
├── docker/                  # Dockerfiles; docker-compose.yml at root
├── tests/                   # 260+ tests incl. vulnerable & secure fixture apps
├── requirements/django_137_requirements.yml
├── rules/requirement_mapping.yml, advisories.yml
├── tools/                   # requirement generator
├── docs/                    # architecture, threat model, SQL schema
├── security-audit.yml       # audit configuration
└── security-audit           # CLI launcher
```

---

## Testing

```bash
python -m pytest tests/ -q        # 267 passing tests
```

Includes intentionally **vulnerable** and **secure** fixture Django apps
(`tests/fixtures/`): the vulnerable one must produce eval/exec/SQLi/XSS/SSRF/
IDOR/AllowAny/DEBUG/hardcoded-secret/unsafe-upload/traversal/weak-crypto
findings; the secure one must produce no Critical/Confirmed findings
(false-positive control).

---

## Security of the tool itself

Authorization gating, secret masking in every stored evidence item, path
confinement, malicious-ZIP rejection (traversal/symlinks), no execution of
scanned code during SAST/settings analysis, loopback-only app sandboxing,
scan timeouts, scrypt-hashed platform users with RBAC + audit log, and
`0600` credential files — see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Limitations

- DAST probes are heuristic; authenticated flows need configured accounts.
- The embedded advisory DB is a curated subset — pin and refresh
  `rules/advisories.yml`, or wire pip-audit/safety for full coverage.
- Network scans cover the configured common port set (extend via
  `network.scan_ports`).
- The in-repo dashboard is a server-served single-page app; the Next.js
  frontend described in the design docs can be dropped in behind the same API.
