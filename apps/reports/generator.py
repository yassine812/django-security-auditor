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


# ---------------------------------------------------------------------------
# 4-axis grouping (Code / Configuration / Dependencies / Network+DAST)
# ---------------------------------------------------------------------------

AXES = [
    ("Axe 1 — Code (SAST)", "sast"),
    ("Axe 2 — Configuration & secrets", "configuration"),
    ("Axe 3 — Dependencies", "dependencies"),
    ("Axe 4 — Network, DAST & security tests", "network"),
]


def _axis_index(item: dict) -> int:
    dk = (item.get("dedup_key") or "")
    src = set(item.get("sources") or [])
    if dk.startswith("sast:") or "sast" in src:
        return 0
    if dk.startswith("config:") or "configuration" in src:
        return 1
    if dk.startswith("dep:") or "dependencies" in src:
        return 2
    return 3


def _axis_groups(audit: Audit) -> list[list[dict]]:
    groups: list[list[dict]] = [[] for _ in AXES]
    for f in sorted(audit.findings, key=lambda x: x["severity"]):
        groups[_axis_index(f)].append(f)
    return groups


def _axis_req_groups(audit: Audit) -> list[list[dict]]:
    groups: list[list[dict]] = [[] for _ in AXES]
    for r in audit.requirement_results:
        groups[_axis_index(r)].append(r)
    return groups


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
# Severity / axis vocabulary shared by every report format
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_MEANING = {
    "Critical": "Exploitable now, severe impact - patch immediately",
    "High": "Serious weakness, likely exploitable - fix before release",
    "Medium": "Real weakness with limited impact - schedule a fix",
    "Low": "Hardening / best practice",
    "Info": "Review input, not a violation",
}
AXIS_TOOLS = {
    0: "SAST (code patterns, taint)",
    1: "Settings / secrets scanner",
    2: "Dependency + advisory scanner",
    3: "Port scanner + DAST + security tests",
}
SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def _axis_short(item: dict) -> str:
    """A1..A4 - the same labels the dashboard uses."""
    return f"A{_axis_index(item) + 1}"


def _pct(n: int, total: int) -> str:
    return f"{(100.0 * n / total):.0f}%" if total else "0%"


def _location(item: dict) -> str:
    """Best available 'where' for a finding: file:line > endpoint > manifest/proof."""
    f = item.get("file")
    if f:
        line = item.get("line")
        return f"{f}:{line}" if line else str(f)
    if item.get("endpoint"):
        return str(item["endpoint"])
    srcs = set(item.get("sources") or [])
    if srcs & {"dependencies"}:
        return f"dependency manifest - {item.get('proof', '')}".strip(" -")
    if srcs & {"network"}:
        return item.get("proof") or "authorized target"
    return item.get("proof") or "-"


def _sorted_findings(audit: Audit) -> list[dict]:
    return sorted(audit.findings,
                  key=lambda f: (SEV_RANK.get(f.get("severity"), 9), f.get("title", "")))


def _hotspots(audit: Audit, limit: int = 10) -> list[tuple[str, int, str]]:
    """Files (or endpoints) carrying the most findings: (where, count, severity mix)."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in audit.findings:
        if f.get("file"):
            key = str(f["file"])
        elif f.get("endpoint"):
            key = str(f["endpoint"])
        elif "dependencies" in (f.get("sources") or []):
            key = "(dependency manifests)"
        elif f.get("sources"):
            key = f"({f['sources'][0]})"
        else:
            key = "(no location)"
        groups[key].append(f)
    rows = []
    for key, fs in groups.items():
        mix = Counter(x["severity"] for x in fs)
        mix_txt = ", ".join(f"{s}: {mix[s]}" for s in SEVERITY_ORDER if mix.get(s))
        rows.append((key, len(fs), mix_txt))
    rows.sort(key=lambda r: (-r[1], r[0]))
    return rows[:limit]


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
        f"<td>{e(f['confidence'])}</td>"
        f"<td>{e(AXES[_axis_index(f)][0])}<div class='small'>{e(', '.join(f.get('sources', [])))}</div></td>"
        f"<td>{e(', '.join(f.get('cwe', [])))}</td>"
        f"<td>{e(f.get('owasp', ''))}</td>"
        f"<td>{e(', '.join(f.get('requirement_ids', [])))}</td>"
        f"<td><code>{e(_location(f))}</code></td>"
        f"<td><code>{e((f.get('proof') or '')[:160])}</code></td></tr>"
        for f in sorted(audit.findings, key=lambda x: x["severity"]))

    # ---- 4-axis sections --------------------------------------------------
    fg = _axis_groups(audit)
    rg = _axis_req_groups(audit)
    axes_html = ""
    for (name, _key), fs, rs in zip(AXES, fg, rg):
        stc = Counter(r["status"] for r in rs)
        sevc = Counter(f["severity"] for f in fs)
        mini = " &middot; ".join(
            f"<span style='color:{STATUS_COLORS[s]}'>{stc.get(s, 0)} {s.replace('_', ' ')}</span>"
            for s in ("PASS", "FAIL", "PARTIAL", "NOT_TESTED", "MANUAL_REVIEW"))
        rows = "".join(
            f"<tr><td>{e(f['title'])}</td>"
            f"<td style='color:{SEV_COLORS.get(f['severity'], '#000')}'>{e(f['severity'])}</td>"
            f"<td>{e(f['confidence'])}</td>"
            f"<td><code>{e(f.get('file') or f.get('endpoint') or '')}"
            f"{(':' + str(f['line'])) if f.get('line') else ''}</code></td>"
            f"<td><code>{e((f.get('proof') or '')[:120])}</code></td>"
            f"<td>{e(fix_for(f)['after'][:220])}</td></tr>"
            for f in fs)
        axes_html += f"""<h2>{name}</h2>
<p class="small" style="font-size:12px">{len(fs)} finding(s) &mdash;
{', '.join(f'{k}: {v}' for k, v in sevc.items()) or 'clean'} &nbsp;|&nbsp;
requirements: {mini}</p>
<table><tr><th>Finding</th><th>Severity</th><th>Confidence</th><th>Location</th>
<th>Vulnerable code</th><th>Exact fix</th></tr>
{rows or '<tr><td colspan=6>No findings on this axis</td></tr>'}</table>
"""
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

    _total = len(audit.findings)
    _sev = _severity_counts(audit)
    sev_meaning_rows = "".join(
        f"<tr><td style='color:{SEV_COLORS.get(s, '#000')}'><b>{s}</b></td><td>{_sev.get(s, 0)}</td>"
        f"<td>{_pct(_sev.get(s, 0), _total)}</td><td>{e(SEVERITY_MEANING[s])}</td></tr>"
        for s in SEVERITY_ORDER)
    axis_share_rows = "".join(
        f"<tr><td>{e(name)}</td><td>{len(fs)}</td><td>{_pct(len(fs), _total)}</td>"
        f"<td>{e(AXIS_TOOLS[i])}</td></tr>"
        for i, ((name, _k), fs) in enumerate(zip(AXES, _axis_groups(audit))))
    priority_rows = "".join(
        f"<tr><td style='color:{SEV_COLORS.get(f['severity'], '#000')}'>"
        f"<b>{e(f['severity'])}</b></td><td>{e(AXES[_axis_index(f)][0])}</td>"
        f"<td><code>{e(_location(f))}</code></td><td>{e(f['title'])}</td>"
        f"<td>{e((f.get('remediation') or '')[:200])}</td></tr>"
        for f in _sorted_findings(audit) if f["severity"] in ("Critical", "High")) \
        or "<tr><td colspan=5>No Critical or High finding.</td></tr>"
    hotspot_rows = "".join(
        f"<tr><td><code>{e(where)}</code></td><td>{n}</td><td>{e(mix)}</td></tr>"
        for where, n, mix in _hotspots(audit, limit=15))
    hotspot_html = ("<h3>Hotspot locations (most findings per file/endpoint)</h3>"
                    "<table><tr><th>File / endpoint</th><th>Findings</th><th>Severity mix</th></tr>"
                    f"{hotspot_rows}</table>") if hotspot_rows else ""

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
<table><tr><th>Severity</th><th>Findings</th><th>Share</th><th>What it means</th></tr>
{sev_meaning_rows}</table>
<h3>Where the findings come from (4 axes)</h3>
<table><tr><th>Axis</th><th>Findings</th><th>Share</th><th>Engines</th></tr>
{axis_share_rows}</table>
<h3>Priority actions (Critical + High) with locations</h3>
<table><tr><th>Severity</th><th>Axis</th><th>Where</th><th>Finding</th><th>Fix</th></tr>
{priority_rows}</table>
{hotspot_html}
<div class="cards">{cards}</div>
<div class="cards">{req_cards}</div>
<p>Requirements total: <b>{len(audit.requirement_results)}</b> &middot;
Findings (deduplicated): <b>{len(audit.findings)}</b></p>

{axes_html}

<h2>Scan environment / pipeline jobs</h2>
<table><tr><th>Job</th><th>Status</th><th>Error</th></tr>{jobs_rows}</table>

<h2>Vulnerabilities (deduplicated findings)</h2>
<table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Confidence</th><th>Axis / engine</th><th>CWE</th>
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

def write_pdf(audit: Audit, path: Path, full: bool = False) -> None:
    """Executive summary PDF (short, ~3-6 pages) or full detail PDF (full=True).

    The executive version answers 'what is critical, where is it, which axis,
    how big is the share' and points to the HTML/JSON reports for evidence.
    """
    from apps.reports.pdf import render_pdf
    if full:
        blocks = _pdf_blocks_full(audit)
    else:
        blocks = _pdf_blocks_executive(audit)
    path.write_bytes(render_pdf(blocks, f"Audit {audit.id}"))


def _pdf_blocks_executive(audit: Audit) -> list[tuple[str, str]]:
    project = audit.project or {}
    score = audit.score or {}
    sev = _severity_counts(audit)
    st = _status_counts(audit)
    total = len(audit.findings)
    blocks: list[tuple[str, str]] = []

    blocks.append(("h1", "Django Security Audit - Executive Report"))
    blocks.append(("body", f"Audit {audit.id} - created {audit.created_at}"))
    blocks.append(("body", f"Project: {project.get('name')} "
                           f"({project.get('source_type')}: "
                           f"{project.get('repo_url') or project.get('path') or ''})"))
    if project.get("commit_sha"):
        blocks.append(("body", f"Commit {project.get('commit_sha')} branch {project.get('branch')}"))
    blocks.append(("hr", ""))

    # -- 1. summary ---------------------------------------------------------
    blocks.append(("h2", "1. Summary"))
    blocks.append(("body", f"Security score: {score.get('score')}/100 (indicator only - "
                           "findings and requirement statuses are authoritative)."))
    blocks.append(("body", f"{total} finding(s) across {len(audit.requirement_results)} "
                           "evaluated requirements."))
    blocks.append(("th:0,80,200,320", "Severity|Findings|Share|What it means"))
    for s in SEVERITY_ORDER:
        n = sev.get(s, 0)
        blocks.append((f"t:0,80,200,320",
                       f"{s}|{n}|{_pct(n, total)}|{SEVERITY_MEANING[s]}"))
    blocks.append(("t:0,80,200,320", f"TOTAL|{total}|100%|"))
    blocks.append(("body", "Requirements: " + ", ".join(
        f"{k} {v}" for k, v in sorted(st.items()))))

    # -- 2. axes ------------------------------------------------------------
    blocks.append(("h2", "2. Where the findings are (4 axes)"))
    blocks.append(("th:0,140,190,250", "Axis|Findings|Share|Engines"))
    for i, ((name, _key), fs) in enumerate(zip(AXES, _axis_groups(audit))):
        sevc = Counter(f["severity"] for f in fs)
        mix = ", ".join(f"{s} {sevc[s]}" for s in SEVERITY_ORDER if sevc.get(s)) or "clean"
        blocks.append(("t:0,140,190,250",
                       f"{name}|{len(fs)}|{_pct(len(fs), total)}|{AXIS_TOOLS[i]} ({mix})"))

    # -- 3. priority actions ------------------------------------------------
    prio = [f for f in _sorted_findings(audit) if f["severity"] in ("Critical", "High")]
    blocks.append(("h2", "3. Priority actions (Critical + High)"))
    if not prio:
        blocks.append(("body", "No Critical or High finding in this run - see the full report "
                               "for Medium/Low hardening items."))
    else:
        blocks.append(("th:0,45,75,255", "Sev|Axis|Where|Finding"))
        for f in prio[:30]:
            axis_short = _axis_short(f)
            blocks.append(("t:0,45,75,255",
                           f"{f['severity']}|{axis_short}|{_location(f)}|{f['title']}"))
            fix = (f.get("remediation") or "").strip()
            if fix:
                blocks.append(("kv", f"      fix: {fix[:220]}"))
        if len(prio) > 30:
            blocks.append(("body", f"... and {len(prio) - 30} more Critical/High findings "
                                   "(see the full report or findings.csv)."))

    # -- 4. hotspot locations ----------------------------------------------
    hot = _hotspots(audit)
    if hot:
        blocks.append(("h2", "4. Hotspot locations (most findings per file/endpoint)"))
        blocks.append(("th:0,240,290,470", "File / endpoint|Findings|Severity mix|"))
        for where, n, mix in hot:
            blocks.append(("t:0,240,290,470", f"{where}|{n}|{mix}|"))

    # -- 5. requirements coverage ------------------------------------------
    blocks.append(("h2", "5. Requirements coverage"))
    blocks.append(("th:0,150,210,300", "Status|Requirements|Share|Meaning"))
    status_meaning = {
        "PASS": "verified by automated evidence",
        "FAIL": "violation confirmed",
        "PARTIAL": "partially covered",
        "NOT_TESTED": "no automated coverage - open",
        "MANUAL_REVIEW": "needs a human check",
        "NOT_APPLICABLE": "not applicable to this project",
    }
    for s in ("PASS", "FAIL", "PARTIAL", "NOT_TESTED", "MANUAL_REVIEW", "NOT_APPLICABLE"):
        n = st.get(s, 0)
        if not n:
            continue
        blocks.append(("t:0,150,210,300",
                       f"{s}|{n}|{_pct(n, len(audit.requirement_results))}|{status_meaning[s]}"))
    fails = [r["requirement_id"] for r in audit.requirement_results if r["status"] == "FAIL"]
    if fails:
        blocks.append(("body", "FAILED requirements: " + ", ".join(fails[:40])
                               + (f" (+{len(fails) - 40} more)" if len(fails) > 40 else "")))

    # -- 6. coverage / jobs --------------------------------------------------
    blocks.append(("h2", "6. Scanners and coverage"))
    for j in audit.jobs:
        blocks.append(("kv", f"{j['name']}: {j['status']}"
                             + (f" ({j.get('error')})" if j.get("error") else "")))

    # -- 7. limitations ------------------------------------------------------
    blocks.append(("h2", "7. Limitations - what is NOT proven"))
    for x in _limitations(audit):
        blocks.append(("bullet", x))

    # -- 8. where to look next ----------------------------------------------
    blocks.append(("h2", "8. Full detail"))
    blocks.append(("body", "Every finding with evidence, request/response, exact code fix and "
                           "requirement mapping is in the detailed artefacts of this audit:"))
    blocks.append(("kv", "reports/report.html - full detail, printable"))
    blocks.append(("kv", "reports/report.pdf (this file) - executive summary"))
    blocks.append(("kv", "reports/report-full.pdf - full detail as PDF"))
    blocks.append(("kv", "reports/findings.csv - one row per finding (sort/filter in Excel)"))
    blocks.append(("kv", "reports/report.json - machine-readable audit state"))
    blocks.append(("body", "A high score or a lack of findings is NOT proof the application is "
                           "secure. Untested and manual-review requirements remain open."))
    return blocks


def _pdf_blocks_full(audit: Audit) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    project = audit.project or {}
    score = audit.score or {}
    sev = score.get("findings_by_severity", _severity_counts(audit))
    st = _status_counts(audit)
    total = len(audit.findings)

    blocks.append(("h1", "Django Security Audit Report"))
    blocks.append(("body", f"Audit {audit.id} - created {audit.created_at}"))

    blocks.append(("h2", "1. Executive summary"))
    blocks.append(("body", f"Security score: {score.get('score')}/100 (summary metric only - "
                           "findings and requirement statuses are authoritative)."))
    blocks.append(("th:0,80,200,320", "Severity|Findings|Share|What it means"))
    for s in SEVERITY_ORDER:
        n = sev.get(s, 0)
        blocks.append(("t:0,80,200,320", f"{s}|{n}|{_pct(n, total)}|{SEVERITY_MEANING[s]}"))
    blocks.append(("body", "Requirements: " + ", ".join(
        f"{k}: {v}" for k, v in sorted(st.items()))))

    blocks.append(("h2", "1bis. Results by axis (4 axes)"))
    for (name, _key), fs, rs in zip(AXES, _axis_groups(audit), _axis_req_groups(audit)):
        sevc = Counter(f["severity"] for f in fs)
        stc = Counter(r["status"] for r in rs)
        blocks.append(("kv", f"{name}: {len(fs)} finding(s) "
                             f"[{', '.join(f'{k}: {v}' for k, v in sevc.items()) or 'clean'}]; "
                             f"requirements [{', '.join(f'{k}: {v}' for k, v in stc.items())}]"))

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
    for f in _sorted_findings(audit):
        blocks.append(("h3", f"[{f['severity']}/{f['confidence']}] {f['title']}"))
        blocks.append(("body", f"{f['description'][:300]}"))
        blocks.append(("kv", f"axis: {AXES[_axis_index(f)][0]}  where: {_location(f)}"))
        blocks.append(("kv", f"CWE: {', '.join(f.get('cwe', []))}  OWASP: {f.get('owasp', '')}  "
                             f"requirements: {', '.join(f.get('requirement_ids', []))}"))
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
    return blocks


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
    write_pdf(audit, d / "report.pdf")                 # executive summary (short)
    paths["pdf"] = str(d / "report.pdf")
    write_pdf(audit, d / "report-full.pdf", full=True)  # every finding + evidence + fixes
    paths["pdf_full"] = str(d / "report-full.pdf")
    return paths
