"""Report generation: PDF, HTML, JSON, CSV (spec 27).

All reports are derived from the persisted audit state.  The PDF/HTML reports
contain every section required by the specification, including limitations:
the platform never claims the application is secure - it reports coverage.
"""
from __future__ import annotations

import csv
import html
import io
import json
from collections import Counter, defaultdict
from pathlib import Path

from apps.audits.models import Audit, AuditStore
from apps.reports.fix_examples import fix_for

SEV_COLORS = {"Critical": "#7f1d1d", "High": "#b91c1c", "Medium": "#d97706",
              "Low": "#2563eb", "Info": "#6b7280"}
STATUS_COLORS = {"PASS": "#059669", "FAIL": "#dc2626", "PARTIAL": "#d97706",
                 "NOT_TESTED": "#6b7280", "NOT_APPLICABLE": "#9ca3af",
                 "MANUAL_REVIEW": "#7c3aed"}


# ---------------------------------------------------------------------------
# shared section extraction
# ---------------------------------------------------------------------------

def _severity_counts(audit: Audit) -> dict:
    return dict(Counter(f["severity"] for f in audit.findings))


def _status_counts(audit: Audit) -> dict:
    return dict(Counter(r["status"] for r in audit.requirement_results))


def _cwe_map(audit: Audit) -> dict:
    m = defaultdict(list)
    for f in audit.findings:
        for c in f.get("cwe", []):
            m[c].append(f["title"])
    return m


def _owasp_map(audit: Audit) -> dict:
    m = defaultdict(list)
    for f in audit.findings:
        if f.get("owasp"):
            m[f["owasp"]].append(f["title"])
    return m


def _limitations(audit: Audit) -> list[str]:
    items = []
    for job in audit.jobs:
        if job["status"] in ("FAILED", "SKIPPED"):
            items.append(f"{job['name']}: {job['status']} - {job.get('error') or 'not run'}")
    n_not_tested = _status_counts(audit).get("NOT_TESTED", 0)
    n_manual = _status_counts(audit).get("MANUAL_REVIEW", 0)
    if n_not_tested:
        items.append(f"{n_not_tested} requirements could not be tested automatically and "
                     "remain NOT_TESTED - absence of findings is not proof of security.")
    if n_manual:
        items.append(f"{n_manual} requirements require manual review.")
    items.append("DAST probes are heuristic; a clean result does not guarantee absence of "
                 "vulnerabilities.")
    items.append("Network scanning was limited to explicitly authorized targets.")
    return items


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def write_json(audit: Audit, path: Path) -> None:
    path.write_text(json.dumps(audit.to_dict(), indent=2, default=str), encoding="utf-8")


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def write_csv(audit: Audit, dirpath: Path) -> list[str]:
    paths = []
    fp = dirpath / "findings.csv"
    with open(fp, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "title", "severity", "confidence", "category", "cwe", "owasp",
                    "requirements", "sources", "file", "line", "endpoint", "status",
                    "retest_status", "remediation"])
        for f in audit.findings:
            w.writerow([f["id"], f["title"], f["severity"], f["confidence"], f["category"],
                        ";".join(f.get("cwe", [])), f.get("owasp", ""),
                        ";".join(f.get("requirement_ids", [])), ";".join(f.get("sources", [])),
                        f.get("file") or "", f.get("line") or "", f.get("endpoint") or "",
                        f.get("status", ""), f.get("retest_status") or "",
                        f.get("remediation", "")])
    paths.append(str(fp))

    rp = dirpath / "requirements.csv"
    with open(rp, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["requirement_id", "status", "sources", "findings", "notes"])
        for r in audit.requirement_results:
            w.writerow([r["requirement_id"], r["status"], ";".join(r.get("sources", [])),
                        ";".join(r.get("finding_ids", [])),
                        " | ".join(r.get("notes", []))[:500]])
    paths.append(str(rp))
    return paths


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def write_html(audit: Audit, path: Path) -> None:
    sev = _severity_counts(audit)
    st = _status_counts(audit)
    e = lambda s: html.escape(str(s)) if s is not None else ""

    cards = "".join(
        f'<div class="card" style="border-left:6px solid {SEV_COLORS[s]}">'
        f'<div class="num">{sev.get(s, 0)}</div><div>{s}</div></div>'
        for s in ("Critical", "High", "Medium", "Low", "Info"))
    req_cards = "".join(
        f'<div class="card"><div class="num">{st.get(s, 0)}</div>'
        f'<div style="color:{STATUS_COLORS[s]}">{s.replace("_", " ")}</div></div>'
        for s in ("PASS", "FAIL", "PARTIAL", "NOT_TESTED", "MANUAL_REVIEW"))

    findings_rows = "".join(
        f"<tr><td>{e(f['id'])}</td><td>{e(f['title'])}</td>"
        f"<td style='color:{SEV_COLORS.get(f['severity'], '#000')}'>{e(f['severity'])}</td>"
        f"<td>{e(f['confidence'])}</td><td>{e(', '.join(f.get('cwe', [])))}</td>"
        f"<td>{e(f.get('owasp', ''))}</td>"
        f"<td>{e(', '.join(f.get('requirement_ids', [])))}</td>"
        f"<td>{e(f.get('file') or f.get('endpoint') or '')}</td>"
        f"<td>{e(f.get('line') or '')}</td>"
        f"<td><code>{e((f.get('proof') or '')[:160])}</code></td></tr>"
        for f in sorted(audit.findings, key=lambda x: x["severity"]))

    # precise remediation blocks (what to fix exactly)
    fix_blocks = "".join(
        (lambda fx: f"""<div class=\"banner\" style=\"border-left:6px solid {SEV_COLORS.get(f['severity'],'#334155')}\">
 <b>[{e(f['severity'])}] {e(f['title'])}</b> &mdash; <code>{e(f.get('file') or f.get('endpoint') or '')}{(':' + str(f['line'])) if f.get('line') else ''}</code><br>
 {('<b>Vulnerable code:</b> <code>' + e(f.get('proof') or '') + '</code><br>') if f.get('proof') else ''}
 {('<b>Why it matters:</b> ' + e(fx['problem']) + '<br>') if fx['problem'] else ''}
 <b>Instead of:</b><pre style="background:#0b1220;padding:8px;border-radius:6px;overflow:auto">{e(fx['before'])}</pre>
 <b>Do this:</b><pre style="background:#0b1220;padding:8px;border-radius:6px;overflow:auto">{e(fx['after'])}</pre>
 <b>Remediation:</b> {e(f.get('remediation', ''))}
 </div>""")(fix_for(f))
        for f in sorted(audit.findings, key=lambda x: x["severity"]))

    req_rows = "".join(
        f"<tr><td>{e(r['requirement_id'])}</td>"
        f"<td style='color:{STATUS_COLORS.get(r['status'], '#000')}'>{e(r['status'])}</td>"
        f"<td>{e(', '.join(r.get('sources', [])))}</td>"
        f"<td>{e(' | '.join(r.get('notes', []))[:300])}</td></tr>"
        for r in audit.requirement_results)

    jobs_rows = "".join(
        f"<tr><td>{e(j['name'])}</td><td>{e(j['status'])}</td><td>{e(j.get('error') or '')}</td></tr>"
        for j in audit.jobs)

    project = audit.project or {}
    score = audit.score or {}
    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Security Audit Report - {e(audit.id)}</title>
<style>
 body{{font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}}
 .wrap{{max-width:1200px;margin:0 auto;padding:24px}}
 h1{{font-size:22px}} h2{{font-size:16px;margin-top:34px;border-bottom:1px solid #334155;padding-bottom:6px}}
 .cards{{display:flex;flex-wrap:wrap;gap:12px;margin:14px 0}}
 .card{{background:#1e293b;border-radius:8px;padding:10px 18px;min-width:110px}}
 .card .num{{font-size:26px;font-weight:700}}
 table{{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}}
 th,td{{border:1px solid #334155;padding:6px 8px;text-align:left;vertical-align:top}}
 th{{background:#1e293b}}
 .banner{{background:#1e293b;border-radius:10px;padding:16px;margin:12px 0}}
 .disclaimer{{background:#7c2d12;border-radius:8px;padding:10px 14px;font-size:13px}}
 code{{background:#0b1220;padding:1px 5px;border-radius:4px}}
</style></head><body><div class="wrap">
<h1>Django Security Audit Report</h1>
<div class="banner">
 <b>Audit:</b> {e(audit.id)} &nbsp; <b>Project:</b> {e(project.get('name'))} &nbsp;
 <b>Source:</b> {e(project.get('source_type'))} {e(project.get('repo_url') or project.get('path') or '')}
 {('<br><b>Commit:</b> <code>' + e(project.get('commit_sha')) + '</code> <b>Branch:</b> ' + e(project.get('branch'))) if project.get('commit_sha') else ''}
 <br><b>Created:</b> {e(audit.created_at)} &nbsp; <b>Status:</b> {e(audit.status)}
</div>

<h2>Executive summary</h2>
<div class="banner">Security score: <b>{e(score.get('score'))}/{e(score.get('max', 100))}</b>
(summary metric only - findings and requirement statuses are authoritative)</div>
<div class="cards">{cards}</div>
<div class="cards">{req_cards}</div>
<p>Requirements total: <b>{len(audit.requirement_results)}</b> &middot;
Findings (deduplicated): <b>{len(audit.findings)}</b></p>

<h2>Scan environment / pipeline jobs</h2>
<table><tr><th>Job</th><th>Status</th><th>Error</th></tr>{jobs_rows}</table>

<h2>Vulnerabilities (deduplicated findings)</h2>
<table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Confidence</th><th>CWE</th>
<th>OWASP</th><th>Requirements</th><th>Location</th><th>Line</th><th>Vulnerable code</th></tr>
{findings_rows or '<tr><td colspan=10>No findings</td></tr>'}</table>

<h2>How to fix (exact remediation)</h2>
{fix_blocks or '<p>No findings to remediate.</p>'}

<h2>Requirements coverage ({len(audit.requirement_results)} requirements)</h2>
<table><tr><th>Requirement</th><th>Status</th><th>Sources</th><th>Evidence / notes</th></tr>
{req_rows}</table>

<h2>CWE mapping</h2><ul>{''.join(f'<li><b>{e(k)}</b>: {len(v)} finding(s)</li>' for k, v in _cwe_map(audit).items())}</ul>

<h2>OWASP Top 10 mapping</h2><ul>{''.join(f'<li><b>{e(k)}</b>: {len(v)} finding(s)</li>' for k, v in _owasp_map(audit).items())}</ul>

<h2>Remediation</h2><ul>{''.join(f"<li><b>{e(f['title'])}</b> ({e(f['severity'])}): {e(f.get('remediation', ''))}</li>" for f in audit.findings if f['severity'] in ('Critical', 'High'))}</ul>

<h2>Limitations</h2><ul>{''.join(f'<li>{e(x)}</li>' for x in _limitations(audit))}</ul>
<div class="disclaimer">This report reflects automated and semi-automated verification only.
NOT_TESTED and MANUAL_REVIEW items remain open. A high score does NOT mean the application
is secure: absence of findings is not proof of security.</div>
</div></body></html>"""
    path.write_text(doc, encoding="utf-8")


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def write_pdf(audit: Audit, path: Path) -> None:
    from apps.reports.pdf import render_pdf
    blocks: list[tuple[str, str]] = []
    project = audit.project or {}
    score = audit.score or {}
    sev = score.get("findings_by_severity", _severity_counts(audit))
    st = _status_counts(audit)

    blocks.append(("h1", "Django Security Audit Report"))
    blocks.append(("body", f"Audit {audit.id} - created {audit.created_at}"))

    blocks.append(("h2", "1. Executive summary"))
    blocks.append(("body", f"Security score: {score.get('score')}/100 (summary metric only - "
                           "findings and requirement statuses are authoritative)."))
    blocks.append(("body", "Findings by severity: " + ", ".join(
        f"{k}: {v}" for k, v in sev.items())))
    blocks.append(("body", "Requirements: " + ", ".join(
        f"{k}: {v}" for k, v in sorted(st.items()))))

    blocks.append(("h2", "2. Project information"))
    blocks.append(("kv", f"name: {project.get('name')}"))
    blocks.append(("kv", f"source: {project.get('source_type')} "
                         f"{project.get('repo_url') or project.get('path') or ''}"))
    if project.get("commit_sha"):
        blocks.append(("kv", f"commit: {project.get('commit_sha')} branch: {project.get('branch')}"))

    blocks.append(("h2", "3. Scan environment"))
    for j in audit.jobs:
        blocks.append(("kv", f"{j['name']}: {j['status']}"
                             + (f" ({j.get('error')})" if j.get("error") else "")))

    blocks.append(("h2", "4. Requirements coverage"))
    blocks.append(("body", f"{len(audit.requirement_results)} requirements evaluated."))
    for r in audit.requirement_results:
        if r["status"] == "FAIL":
            blocks.append(("kv", f"{r['requirement_id']} FAIL - {' | '.join(r['notes'])[:160]}"))

    blocks.append(("h2", "5. Requirements requiring manual review"))
    for r in audit.requirement_results:
        if r["status"] == "MANUAL_REVIEW":
            blocks.append(("kv", f"{r['requirement_id']}"))

    blocks.append(("h2", "6. SAST results"))
    blocks.append(("body", f"Files scanned: {audit.sast_data.get('files_scanned', 'n/a')}, "
                           f"findings attributed to SAST: "
                           f"{sum(1 for f in audit.findings if 'sast' in f.get('sources', []))}"))

    blocks.append(("h2", "7. Dependency results"))
    d = audit.dependencies_report or {}
    blocks.append(("body", f"Packages: {d.get('total', 'n/a')}, pinned: {d.get('pinned', 'n/a')}, "
                           f"unpinned: {d.get('unpinned', 'n/a')}, vulnerable entries: "
                           f"{d.get('vulnerable', 'n/a')}"))

    blocks.append(("h2", "8. Network results"))
    n = audit.network_report or {}
    for host, info in (n.get("hosts") or {}).items():
        s = (info.get("summary") or {})
        blocks.append(("kv", f"{host}: open={s.get('open')} closed={s.get('closed')} "
                             f"filtered={s.get('filtered')} method={info.get('method')}"))

    blocks.append(("h2", "9. DAST results"))
    da = audit.dast_report or {}
    blocks.append(("body", f"base_url: {da.get('base_url', 'not started')}, checks: "
                           f"{da.get('checks_run', 0)}"))

    blocks.append(("h2", "10. Vulnerabilities"))
    for f in sorted(audit.findings, key=lambda x: x["severity"]):
        blocks.append(("h3", f"[{f['severity']}/{f['confidence']}] {f['title']}"))
        blocks.append(("body", f"{f['description'][:300]}"))
        blocks.append(("kv", f"CWE: {', '.join(f.get('cwe', []))}  OWASP: {f.get('owasp', '')}  "
                             f"requirements: {', '.join(f.get('requirement_ids', []))}"))
        if f.get("file"):
            blocks.append(("kv", f"location: {f.get('file')}:{f.get('line')}"))
        if f.get("endpoint"):
            blocks.append(("kv", f"endpoint: {f.get('endpoint')}"))
        blocks.append(("kv", f"evidence: {f.get('proof', '')[:200]}"))
        blocks.append(("kv", f"remediation: {f.get('remediation', '')[:200]}"))
        fx = fix_for(f)
        if fx["after"]:
            blocks.append(("kv", f"fix (instead of): {fx['before'][:180]}"))
            blocks.append(("kv", f"fix (do this): {fx['after'][:400]}"))

    blocks.append(("h2", "11. CWE mapping"))
    for k, v in _cwe_map(audit).items():
        blocks.append(("kv", f"{k}: {len(v)} finding(s)"))
    blocks.append(("h2", "12. OWASP mapping"))
    for k, v in _owasp_map(audit).items():
        blocks.append(("kv", f"{k}: {len(v)} finding(s)"))

    blocks.append(("h2", "13. Remediation priorities"))
    for f in audit.findings:
        if f["severity"] in ("Critical", "High"):
            blocks.append(("kv", f"- {f['title']}: {f.get('remediation', '')[:180]}"))

    if audit.comparison:
        blocks.append(("h2", "14. Retest results"))
        c = audit.comparison
        blocks.append(("body", f"fixed: {len(c.get('fixed', []))}, still present: "
                               f"{len(c.get('still_present', []))}, new: {len(c.get('new', []))}"))
        for t in c.get("fixed", []):
            blocks.append(("kv", f"FIXED: {t}"))
        for t in c.get("still_present", []):
            blocks.append(("kv", f"STILL PRESENT: {t}"))
        for t in c.get("new", []):
            blocks.append(("kv", f"NEW: {t}"))

    blocks.append(("h2", "15. Limitations"))
    for x in _limitations(audit):
        blocks.append(("bullet", x))
    blocks.append(("body", "A high score or a lack of findings is NOT proof the application "
                           "is secure. Untested and manual-review requirements remain open."))

    path.write_bytes(render_pdf(blocks, f"Audit {audit.id}"))


# ---------------------------------------------------------------------------

def generate_all_reports(store: AuditStore, audit: Audit) -> dict:
    d = store.dir_for(audit.id) / "reports"
    d.mkdir(parents=True, exist_ok=True)
    paths = {}
    write_json(audit, d / "report.json")
    paths["json"] = str(d / "report.json")
    write_html(audit, d / "report.html")
    paths["html"] = str(d / "report.html")
    csv_paths = write_csv(audit, d)
    paths["csv"] = csv_paths[0]
    write_pdf(audit, d / "report.pdf")
    paths["pdf"] = str(d / "report.pdf")
    return paths
