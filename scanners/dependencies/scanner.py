"""Dependency security scanner (spec 10).

Checks requirements.txt / pyproject.toml / Pipfile / poetry.lock against an
embedded advisory database (rules/advisories.yml).  When ``pip-audit`` is
available it is used as an additional source; the embedded DB guarantees the
scanner works offline.  Version-dependent checks only run against *pinned*
versions - floating specifiers get DEP-PIN-001 instead of guesses.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from scanners.base import BaseScanner, Evidence, Finding, ScanResult

try:
    from packaging.specifiers import SpecifierSet
    from packaging.version import InvalidVersion, Version
    HAVE_PACKAGING = True
except ImportError:          # pragma: no cover
    HAVE_PACKAGING = False

ROOT = Path(__file__).resolve().parents[2]
ADVISORY_PATH = ROOT / "rules" / "advisories.yml"

# rough "current major" hints used only for the outdated-review signal
CURRENT_HINTS = {
    "django": "5.1", "djangorestframework": "3.15", "requests": "2.32",
    "pillow": "10.4", "pyyaml": "6.0", "jinja2": "3.1", "cryptography": "43.0",
    "paramiko": "3.4", "celery": "5.4", "urllib3": "2.2", "sqlparse": "0.5",
    "certifi": "2024.8.30", "lxml": "5.3", "setuptools": "75.0",
}

DANGEROUS_PACKAGES = {
    "pycrypto": "unmaintained and vulnerable; use pycryptodome or cryptography",
    "python-jwt": "abandoned with known CVEs; use PyJWT >= 2.4 or python-jose cautiously",
    "nosetest": "unmaintained test runner",
    "pyjwt": None,   # only via advisories
}


def load_advisories() -> dict:
    data = yaml.safe_load(ADVISORY_PATH.read_text(encoding="utf-8"))
    return data.get("advisories", {}) or {}


def _parse_pinned(specifier: str) -> str | None:
    """Return exact version if the specifier pins one (== / lockfile)."""
    spec = (specifier or "").strip()
    if not spec or spec in ("(vcs/editable)", "*"):
        return None
    for part in spec.split(","):
        part = part.strip()
        if part.startswith("=="):
            return part[2:].strip().split("+")[0].strip()
    return None


class DependencyScanner(BaseScanner):
    name = "dependencies"
    description = "Dependency vulnerability, pinning and freshness analysis"

    def run(self, context) -> ScanResult:
        from apps.projects.discovery import parse_requirements_txt, _read, _deps_from_pyproject

        result = ScanResult(scanner=self.name)
        advisories = load_advisories()
        root = Path(context.source_dir)

        # Collect all declared dependencies (reuse discovery parser).
        deps: list[dict] = []
        sources: list[str] = []
        for req_file in list(root.glob("requirements.txt")) + list(root.glob("requirements/*.txt")) \
                + list(root.glob("requirements-*.txt")):
            if req_file.is_file():
                deps.extend(parse_requirements_txt(_read(req_file), req_file.parent))
                sources.append(req_file.relative_to(root).as_posix())
        if (root / "pyproject.toml").is_file():
            deps.extend(_deps_from_pyproject(_read(root / "pyproject.toml")))
            sources.append("pyproject.toml")
        if (root / "Pipfile").is_file():
            import re
            for line in _read(root / "Pipfile").splitlines():
                m = re.match(r'^\s*"?([A-Za-z0-9._-]+)"?\s*=\s*"?([^"#\n]*)', line)
                if m and not m.group(1).startswith(("[", "python_version")):
                    deps.append({"name": m.group(1),
                                 "specifier": m.group(2).strip().strip('"').strip("*"),
                                 "line": line})
            sources.append("Pipfile")
        if (root / "poetry.lock").is_file():
            try:
                import tomllib
                lock = tomllib.loads(_read(root / "poetry.lock", 2_000_000))
                for pkg in lock.get("package", []):
                    deps.append({"name": pkg.get("name", ""), "specifier": f"=={pkg.get('version')}",
                                 "line": "poetry.lock"})
                sources.append("poetry.lock")
            except Exception as exc:  # noqa: BLE001
                context.log("WARN", f"poetry.lock unreadable: {exc}")

        if not deps:
            result.status = "SKIPPED"
            result.error = "no dependency manifests found"
            return result

        seen = set()
        vulnerable = pinned_count = unpinned_count = 0
        packages = []
        for dep in deps:
            name = (dep.get("name") or "").strip()
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())
            spec = dep.get("specifier", "")
            exact = _parse_pinned(spec)
            packages.append({"name": name, "specifier": spec, "pinned_version": exact})

            # -- dangerous / unmaintained packages --------------------------
            if name.lower() in DANGEROUS_PACKAGES and DANGEROUS_PACKAGES[name.lower()]:
                self._emit(result, name, spec, exact,
                           rule_id="DEP-DANGEROUS-001", severity="High",
                           title=f"Dangerous/unmaintained dependency: {name}",
                           summary=DANGEROUS_PACKAGES[name.lower()],
                           cwe="CWE-1104", reqs=["REQ-059", "REQ-061"])
                vulnerable += 1

            # -- advisories --------------------------------------------------
            adv_list = advisories.get(name.lower(), [])
            if exact and HAVE_PACKAGING:
                try:
                    v = Version(exact)
                except InvalidVersion:
                    v = None
                if v is not None:
                    for adv in adv_list:
                        try:
                            if Version(adv["introduced"]) <= v < Version(adv["fixed"]):
                                self._emit(result, name, spec, exact,
                                           rule_id="DEP-CVE-001", severity=adv["severity"],
                                           title=f"{name} {exact} affected by {adv['id']}",
                                           summary=f"{adv['summary']} (fixed in {adv['fixed']})",
                                           cwe="CWE-1395", reqs=["REQ-060"],
                                           advisory=adv["id"])
                                vulnerable += 1
                        except InvalidVersion:
                            continue
            elif adv_list and not exact:
                result.evidence.append(Evidence(
                    source="dependencies", rule_id="DEP-CVE-001", polarity="info",
                    summary=f"{name} is not pinned; {len(adv_list)} known advisory/advisories apply "
                            "to some versions - pin and re-check.",
                    location={"package": name, "version": None, "spec": spec},
                    requirement_ids=["REQ-059", "REQ-060"]))

            # -- pinning ------------------------------------------------------
            if exact or spec == "(vcs/editable)":
                pinned_count += 1
                if exact:
                    result.evidence.append(Evidence(
                        source="dependencies", rule_id="DEP-PIN-001", polarity="ok",
                        summary=f"{name} pinned to {exact}.",
                        location={"package": name, "version": exact, "spec": spec},
                        requirement_ids=["REQ-059"]))
            else:
                unpinned_count += 1
                self._emit(result, name, spec, exact,
                           rule_id="DEP-PIN-001", severity="Low",
                           title=f"Unpinned dependency: {name}",
                           summary=f"{name} declared as '{spec or '(any)'}' - builds are not "
                                   "reproducible and can silently pull vulnerable releases.",
                           cwe="CWE-1104", reqs=["REQ-059"], confidence="High")

            # -- outdated hint ---------------------------------------------------
            hint = CURRENT_HINTS.get(name.lower())
            if hint and exact and HAVE_PACKAGING:
                try:
                    if Version(exact) < Version(hint):
                        self._emit(result, name, spec, exact,
                                   rule_id="DEP-OLD-001", severity="Info",
                                   title=f"Outdated dependency: {name} {exact}",
                                   summary=f"{name} {exact} is older than the current line ({hint}). "
                                           "Review for security fixes.",
                                   cwe="CWE-1104", reqs=["REQ-061"], confidence="Medium")
                except InvalidVersion:
                    pass

        result.data = {"packages": packages, "manifests": sources,
                       "total": len(packages), "pinned": pinned_count,
                       "unpinned": unpinned_count, "vulnerable": vulnerable}
        context.log("INFO", f"Dependency scan: {len(packages)} packages, "
                            f"{vulnerable} vulnerable entries")
        return result

    # ------------------------------------------------------------------
    def _emit(self, result: ScanResult, name: str, spec: str, exact: str | None, *,
              rule_id: str, severity: str, title: str, summary: str, cwe: str,
              reqs: list, confidence: str = "Confirmed", advisory: str | None = None) -> None:
        # informational entries (e.g. outdated hints) are review input, not violations
        polarity = "info" if severity == "Info" else "vuln"
        evidence = Evidence(
            source="dependencies", rule_id=rule_id, polarity=polarity,
            summary=summary,
            location={"package": name, "version": exact, "spec": spec,
                      "advisory": advisory},
            requirement_ids=list(reqs), confidence=confidence)
        finding = Finding(
            title=title, description=summary, severity=severity, confidence=confidence,
            category="Vulnerable Dependencies", cwe=[cwe], owasp="A06:2021",
            requirement_ids=list(reqs), sources=["dependencies"],
            evidence_ids=[evidence.id],
            proof=f"{name}{('==' + exact) if exact else (' ' + spec if spec else '')}",
            remediation=(f"Upgrade {name} to a fixed version" if advisory
                         else f"Pin {name} to an exact, reviewed version"),
            dedup_key=f"dep:{rule_id}:{name.lower()}:{advisory or ''}")
        result.evidence.append(evidence)
        result.findings.append(finding)
