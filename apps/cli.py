"""security-audit CLI (spec 31).

Examples:
    security-audit full ./my-django-project --yes
    security-audit github https://github.com/org/repo --branch main --yes
    security-audit sast ./project
    security-audit network 127.0.0.1
    security-audit dast http://127.0.0.1:8000
    security-audit requirements ./project
    security-audit report AUDIT_ID
    security-audit retest AUDIT_ID ./project --yes
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apps.audits.config import load_config, write_default_config       # noqa: E402
from apps.audits.models import AuditStore                               # noqa: E402
from apps.audits.pipeline import AuditPipeline                          # noqa: E402
from apps.audits.retest import run_retest                               # noqa: E402

AUTHORIZATION_PROMPT = (
    "I confirm that I am authorized to security-test this application and its "
    "infrastructure.")

DEFAULT_WORKDIR = str(ROOT / "workdir")


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _printer(audit):
    def fn(level: str, message: str):
        audit.log(level, message)
        print(f"[{_ts()}] {level:5s} {message}", flush=True)
    return fn


def _confirm_authorization(args) -> bool:
    if getattr(args, "yes", False):
        print(f"[authorization] assumed confirmed via --yes: \"{AUTHORIZATION_PROMPT}\"")
        return True
    if not sys.stdin.isatty():
        print("[authorization] no TTY: network/DAST steps will be skipped unless --yes "
              "is passed.")
        return False
    print("\n" + AUTHORIZATION_PROMPT)
    answer = input("Type 'yes' to confirm: ").strip().lower()
    return answer in ("yes", "y")


def _run(args, project: dict, steps: str = "full"):
    store = AuditStore(args.workdir)
    pipeline = AuditPipeline(store, args.config)
    authorized = _confirm_authorization(args)
    audit = pipeline.create_audit(project, authorization_confirmed=authorized)
    audit.log = _wrap_log(audit, audit.log)
    print(f"[{_ts()}] AUDIT {audit.id} created for '{project['name']}' ({steps})")
    audit = pipeline.run_full(audit)
    _print_final_summary(audit)
    return audit


def _wrap_log(audit, original):
    def fn(level, message):
        original(level, message)
        print(f"[{_ts()}] {level:5s} {message}", flush=True)
    return fn


def _print_final_summary(audit) -> None:
    from collections import Counter
    st = Counter(r["status"] for r in audit.requirement_results)
    sev = Counter(f["severity"] for f in audit.findings)
    sources = Counter()
    for f in audit.findings:
        for s in f.get("sources", []):
            sources[s] += 1
    project = audit.project or {}
    print()
    print("=" * 64)
    print("AUDIT COMPLETE")
    print("=" * 64)
    print(f"Project:   {project.get('name')}")
    if project.get("commit_sha"):
        print(f"Version:   commit {project.get('commit_sha')} "
              f"(branch {project.get('branch')})")
    print(f"Requirements: {len(audit.requirement_results)}")
    for s in ("PASS", "FAIL", "PARTIAL", "NOT_TESTED", "MANUAL_REVIEW", "NOT_APPLICABLE"):
        print(f"  {s:14s} {st.get(s, 0)}")
    print(f"Findings:  {len(audit.findings)} (deduplicated)")
    for s in ("Critical", "High", "Medium", "Low", "Info"):
        print(f"  {s:10s} {sev.get(s, 0)}")
    score = audit.score or {}
    print(f"Score:     {score.get('score')}/100 (summary metric only)")
    if audit.comparison:
        c = audit.comparison["summary"]
        print(f"Retest:    fixed={c['fixed']} still_present={c['still_present']} "
              f"new={c['new']}")
    print("\nTop findings:")
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    for f in sorted(audit.findings, key=lambda x: order.get(x["severity"], 9))[:10]:
        print(f"  [{f['severity']:8s}] {f['title']}"
              f"{' @ ' + (f.get('file') or f.get('endpoint') or '') if (f.get('file') or f.get('endpoint')) else ''}")
    manual = [r for r in audit.requirement_results if r["status"] == "MANUAL_REVIEW"]
    if manual:
        print(f"\nRequirements requiring manual review: {len(manual)} "
              f"({', '.join(r['requirement_id'] for r in manual[:12])}{'...' if len(manual) > 12 else ''})")
    if audit.report_paths:
        print("\nReports:")
        for kind, p in audit.report_paths.items():
            print(f"  {kind:5s} {p}")
    print("=" * 64)


# ---------------------------------------------------------------------------
# subcommands
# ---------------------------------------------------------------------------

def cmd_full(args):
    project = {"name": Path(args.path).name or "project", "source_type": "local",
               "path": str(Path(args.path).expanduser().resolve())}
    _run(args, project)


def cmd_github(args):
    from apps.projects.sources import acquire_github
    store = AuditStore(args.workdir)
    dest = str(Path(store.root) / f"clone-{Path(args.url).stem}-{datetime.now().strftime('%H%M%S')}")
    info = acquire_github(args.url, dest, branch=args.branch, commit=args.commit,
                          token=args.token)
    project = {"name": Path(args.url).rstrip("/").name, "source_type": "github",
               "path": info["path"], "repo_url": info["repo_url"],
               "branch": info["branch"], "commit_sha": info["commit_sha"]}
    print(f"[{_ts()}] cloned {info['repo_url']} @ {info['commit_sha'][:12]} "
          f"(branch {info['branch']})")
    _run(args, project)


def cmd_zip(args):
    from apps.projects.sources import acquire_zip
    store = AuditStore(args.workdir)
    dest = str(Path(store.root) / f"zip-{datetime.now().strftime('%H%M%S')}")
    info = acquire_zip(args.archive, dest)
    project = {"name": Path(args.archive).stem, "source_type": "zip",
               "path": info["path"]}
    _run(args, project)


def _single_scanner(args, scanner_cls, ctx_kwargs=None):
    from scanners.base import AuditContext
    config = load_config(args.config)
    ctx = AuditContext(source_dir=str(Path(args.path).expanduser().resolve()),
                       config=config, authorization_confirmed=True)
    for k, v in (ctx_kwargs or {}).items():
        setattr(ctx, k, v)
    result = scanner_cls().safe_run(ctx)
    print(f"scanner: {result.scanner} status={result.status}")
    if result.error:
        print(f"error: {result.error}")
    for f in result.findings:
        print(f"[{f.severity:8s}/{f.confidence:9s}] {f.title} @ "
              f"{f.file or f.endpoint or ''}:{f.line or ''}")
    print(f"total findings: {len(result.findings)}, evidence items: {len(result.evidence)}")
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, default=str))


def cmd_sast(args):
    from scanners.sast.scanner import SASTScanner
    _single_scanner(args, SASTScanner)


def cmd_deps(args):
    from apps.projects.discovery import discover_project
    from scanners.dependencies.scanner import DependencyScanner
    from scanners.base import AuditContext
    config = load_config(args.config)
    ctx = AuditContext(source_dir=str(Path(args.path).expanduser().resolve()), config=config)
    ctx.profile = discover_project(ctx.source_dir)
    result = DependencyScanner().safe_run(ctx)
    print(f"scanner: dependencies status={result.status}")
    for f in result.findings:
        print(f"[{f.severity:8s}] {f.title}")
    print(f"total findings: {len(result.findings)}")


def cmd_requirements(args):
    from apps.projects.discovery import discover_project
    from apps.requirements_engine.loader import load_requirements
    from scanners.configuration.django_settings import DjangoSettingsScanner
    from scanners.sast.scanner import SASTScanner
    from scanners.base import AuditContext
    from apps.requirements_engine.engine import compute_status
    config = load_config(args.config)
    src = str(Path(args.path).expanduser().resolve())
    ctx = AuditContext(source_dir=src, config=config)
    ctx.profile = discover_project(src)
    evidence = []
    for scanner in (SASTScanner(), DjangoSettingsScanner()):
        r = scanner.safe_run(ctx)
        evidence += [e.to_dict() for e in r.evidence]
    job_states = {"sast": "SUCCESS", "settings": "SUCCESS"}
    from collections import defaultdict
    by_req = defaultdict(list)
    for ev in evidence:
        for rid in ev["requirement_ids"]:
            by_req[rid].append(ev)
    reqs = load_requirements()
    counts = defaultdict(int)
    for req in reqs:
        res = compute_status(req, by_req.get(req.id, []), job_states)
        counts[res["status"]] += 1
        if args.verbose and res["status"] != "NOT_TESTED":
            print(f"{req.id} [{req.name}] -> {res['status']}")
    print(f"requirements evaluated statically: {dict(counts)} "
          "(runtime checks require 'security-audit full')")


def cmd_network(args):
    from scanners.base import AuditContext
    from scanners.network.scanner import NetworkScanner
    config = load_config(args.config)
    config.setdefault("network", {})["authorized_targets"] = [args.target]
    authorized = _confirm_authorization(args)
    ctx = AuditContext(source_dir=".", config=config, authorization_confirmed=authorized)
    result = NetworkScanner().safe_run(ctx)
    print(f"scanner: network status={result.status} {result.error or ''}")
    for f in result.findings:
        print(f"[{f.severity:8s}] {f.title}")
    for ev in result.evidence:
        if ev.polarity == "info":
            print(f"[info] {ev.summary}")


def cmd_dast(args):
    from scanners.base import AuditContext
    from scanners.dast.scanner import DASTScanner
    config = load_config(args.config)
    authorized = _confirm_authorization(args)
    ctx = AuditContext(source_dir=".", config=config, authorization_confirmed=authorized)
    ctx.base_url = args.url.rstrip("/")
    ctx.endpoints = []
    result = DASTScanner().safe_run(ctx)
    print(f"scanner: dast status={result.status} {result.error or ''}")
    for f in result.findings:
        print(f"[{f.severity:8s}] {f.title} @ {f.endpoint or ''}")
    for ev in result.evidence:
        if ev.polarity == "ok":
            print(f"[ok] {ev.summary}")


def cmd_report(args):
    store = AuditStore(args.workdir)
    audit = store.load(args.audit_id)
    from apps.reports.generator import generate_all_reports
    paths = generate_all_reports(store, audit)
    for kind, p in paths.items():
        print(f"{kind}: {p}")


def cmd_list(args):
    store = AuditStore(args.workdir)
    for item in store.list_audits():
        print(f"{item['id']}  {item.get('created_at', '')}  {item.get('status', '')}  "
              f"{item.get('project', '')}")


def cmd_show(args):
    store = AuditStore(args.workdir)
    audit = store.load(args.audit_id)
    _print_final_summary(audit)


def cmd_retest(args):
    store = AuditStore(args.workdir)
    authorized = _confirm_authorization(args)
    audit = run_retest(store, args.audit_id,
                       str(Path(args.path).expanduser().resolve()),
                       authorization_confirmed=authorized, config_path=args.config)
    _print_final_summary(audit)


def cmd_init(args):
    p = write_default_config(args.output)
    print(f"wrote {p}")


def cmd_serve(args):
    try:
        import uvicorn
        from apps.api.server import build_app
    except ImportError as exc:
        print(f"API server dependencies missing ({exc}). Install with: "
              "pip install -e '.[api]'")
        return 1
    app = build_app(AuditStore(args.workdir), config_path=args.config)
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def cmd_users(args):
    from apps.users.auth import UserStore
    import getpass
    users = UserStore(args.workdir)
    pw = args.password or getpass.getpass("new password: ")
    if args.users_action == "add":
        users.create_user(args.username, pw, args.role)
        print(f"user '{args.username}' created with role {args.role}")
    else:
        users.set_password(args.username, pw)
        print(f"password updated for '{args.username}'")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="security-audit",
                                description="Automated Django Security Audit Platform")
    p.add_argument("--workdir", default=DEFAULT_WORKDIR, help="audit workspace directory")
    p.add_argument("--config", default=str(ROOT / "security-audit.yml"),
                   help="path to security-audit.yml")
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp, with_yes=True):
        if with_yes:
            sp.add_argument("--yes", action="store_true",
                            help="confirm scan authorization non-interactively")

    sp = sub.add_parser("full", help="full audit of a local project")
    sp.add_argument("path")
    add_common(sp)
    sp.set_defaults(func=cmd_full)

    sp = sub.add_parser("scan", help="alias of full")
    sp.add_argument("path")
    add_common(sp)
    sp.set_defaults(func=cmd_full)

    sp = sub.add_parser("github", help="clone a repository and audit it")
    sp.add_argument("url")
    sp.add_argument("--branch")
    sp.add_argument("--commit")
    sp.add_argument("--token")
    add_common(sp)
    sp.set_defaults(func=cmd_github)

    sp = sub.add_parser("zip", help="extract an archive and audit it")
    sp.add_argument("archive")
    add_common(sp)
    sp.set_defaults(func=cmd_zip)

    sp = sub.add_parser("sast", help="run SAST only")
    sp.add_argument("path")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_sast)

    sp = sub.add_parser("deps", help="run dependency scan only")
    sp.add_argument("path")
    sp.set_defaults(func=cmd_deps)

    sp = sub.add_parser("requirements", help="static requirements evaluation")
    sp.add_argument("path")
    sp.add_argument("--verbose", action="store_true")
    sp.set_defaults(func=cmd_requirements)

    sp = sub.add_parser("network", help="authorized network scan")
    sp.add_argument("target")
    add_common(sp)
    sp.set_defaults(func=cmd_network)

    sp = sub.add_parser("dast", help="DAST against a running instance")
    sp.add_argument("url")
    add_common(sp)
    sp.set_defaults(func=cmd_dast)

    sp = sub.add_parser("report", help="regenerate reports for an audit")
    sp.add_argument("audit_id")
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("list", help="list audits")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("show", help="show audit summary")
    sp.add_argument("audit_id")
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("retest", help="re-run an audit and compare")
    sp.add_argument("audit_id")
    sp.add_argument("path")
    add_common(sp)
    sp.set_defaults(func=cmd_retest)

    sp = sub.add_parser("init", help="write default security-audit.yml")
    sp.add_argument("--output", default="security-audit.yml")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("serve", help="run the API + dashboard server")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8300)
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser("users", help="manage dashboard users (add / password)")
    usp = sp.add_subparsers(dest="users_action", required=True)
    ua = usp.add_parser("add", help="create a user")
    ua.add_argument("username")
    ua.add_argument("--role", default="analyst", choices=["admin", "analyst", "viewer"])
    ua.add_argument("--password", default=None, help="prompted securely if omitted")
    ua.set_defaults(func=cmd_users)
    up = usp.add_parser("password", help="change a user's password")
    up.add_argument("username")
    up.add_argument("--password", default=None, help="prompted securely if omitted")
    up.set_defaults(func=cmd_users)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    result = args.func(args)
    return result or 0


if __name__ == "__main__":
    raise SystemExit(main())
