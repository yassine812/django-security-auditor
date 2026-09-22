#!/usr/bin/env python3
"""Export a self-contained, read-only HTML snapshot of the dashboard.

The generated file embeds the audit data, so it can be opened from disk or
e-mailed to a colleague: no server, no network, no credentials.

Usage:
    python tools/static_preview.py <workdir> <audit-id> [out.html]
    python tools/static_preview.py workdir audit-fc911f17 preview.html
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def build_snapshot(workdir: str, audit_id: str) -> dict:
    from apps.audits.models import AuditStore

    store = AuditStore(workdir)
    audit = store.load(audit_id)
    audits = []
    for a in store.list_audits():
        audits.append({"id": a.get("id"), "project": a.get("project"),
                       "created_at": a.get("created_at"), "status": a.get("status")})
    from apps.audits.axes import enrich
    return {"audits": audits, "detail": enrich(audit.to_dict()), "projects": []}


def export(workdir: str, audit_id: str, out_path: Path) -> Path:
    dashboard = (ROOT / "frontend" / "dashboard.html").read_text(encoding="utf-8")
    payload = json.dumps(build_snapshot(workdir, audit_id), default=str)
    payload = payload.replace("</", "<\\/")
    injected = f"<script>window.DSA_SNAPSHOT={payload};</script>\n<script>"
    html = dashboard.replace("<script>", injected, 1)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    return out_path


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    workdir, audit_id = argv[1], argv[2]
    out = Path(argv[3]) if len(argv) > 3 else Path(f"{audit_id}-dashboard.html")
    path = export(workdir, audit_id, out)
    print(f"static dashboard snapshot written to {path} ({path.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
