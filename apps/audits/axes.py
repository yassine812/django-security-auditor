"""Axis model shared by the pipeline, the reports and the dashboard.

Four axes:
  A1 Code (SAST)          A2 Configuration & secrets
  A3 Dependencies         A4 Network, DAST & security tests

Findings are placed by their dedup_key prefix / sources.  Requirements are
placed by the scanner_mapping declared in the 137-requirement catalogue, which
is the authoritative source: a requirement that no scanner can cover is still
attached to the axis that owns it (and shows up as NOT_TESTED there).
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

AXES = [
    ("Axe 1 — Code (SAST)", "sast"),
    ("Axe 2 — Configuration & secrets", "configuration"),
    ("Axe 3 — Dépendances", "dependencies"),
    ("Axe 4 — Réseau, DAST & tests de sécurité", "network"),
]
AXIS_TOOLS = {
    0: "SAST (motifs de code, analyse de flux)",
    1: "Analyseur de settings / secrets",
    2: "Analyseur de dépendances + avis CVE",
    3: "Scanner de ports + DAST + tests de sécurité",
}
CATALOGUE = Path(__file__).resolve().parents[2] / "requirements" / "django_137_requirements.yml"


def axis_of_finding(item: dict) -> int:
    dk = (item.get("dedup_key") or "")
    src = set(item.get("sources") or [])
    if dk.startswith("sast:") or "sast" in src:
        return 0
    if dk.startswith("config:") or "configuration" in src:
        return 1
    if dk.startswith("dep:") or "dependencies" in src:
        return 2
    return 3


@lru_cache(maxsize=1)
def _catalogue_axes() -> dict:
    """requirement id -> axis index, from scanner_mapping in the catalogue."""
    mapping: dict[str, int] = {}
    try:
        import yaml
        data = yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))
        reqs = data["requirements"] if isinstance(data, dict) and "requirements" in data else data
    except Exception:  # noqa: BLE001 - catalogue optional at runtime
        return mapping
    order = ("sast", "configuration", "dependencies", "network")
    for req in reqs or []:
        sm = (req.get("scanner_mapping") or {})
        idx = None
        for i, key in enumerate(order):
            if sm.get(key) or (i == 3 and (sm.get("dast") or sm.get("automated"))):
                idx = i
                break
        if idx is None:
            vm = req.get("verification_method") or []
            key = next((k for k in ("sast", "configuration", "dependencies", "network")
                        if k in vm), None)
            idx = ("sast", "configuration", "dependencies", "network").index(key) if key else None
        if idx is None:
            continue
        mapping[str(req.get("id"))] = idx
    return mapping


SCANNER_SOURCES = {"sast", "configuration", "dependencies", "network", "dast", "automated"}


def catalogue_axis(requirement_id: str) -> int | None:
    """Axe déclaré par le catalogue des 137, ou None si l'exigence est transverse."""
    return _catalogue_axes().get(str(requirement_id or ""))


def is_transverse(item: dict) -> bool:
    """True : exigence sans scanner dédié (processus / revue manuelle)."""
    if catalogue_axis(item.get("requirement_id")) is not None:
        return False
    return not (set(item.get("sources") or []) & SCANNER_SOURCES)


def axis_of_requirement(item: dict) -> int:
    """Catalogue axis when known, else fall back to the evidence sources."""
    idx = catalogue_axis(item.get("requirement_id"))
    if idx is not None:
        return idx
    src = set(item.get("sources") or [])
    dk = (item.get("dedup_key") or "")
    if dk.startswith("sast:") or "sast" in src:
        return 0
    if dk.startswith("config:") or "configuration" in src:
        return 1
    if dk.startswith("dep:") or "dependencies" in src:
        return 2
    return 3


def enrich(audit_dict: dict) -> dict:
    """Ajoute l'axe (1-4) à chaque constat/exigence + les métadonnées d'axes.

    Utilisé par l'API (tableau de bord) et par l'export statique, pour que la
    répartition par axe soit identique partout.
    """
    for f in audit_dict.get("findings", []):
        f["axis"] = axis_of_finding(f) + 1
    for r in audit_dict.get("requirement_results", []):
        r["axis"] = axis_of_requirement(r) + 1
        r["transverse"] = is_transverse(r)
    audit_dict["axes"] = [{"id": f"A{i + 1}", "label": AXES[i][0]} for i in range(len(AXES))]
    return audit_dict


def axis_label(idx: int) -> str:
    return AXES[max(0, min(idx, len(AXES) - 1))][0]


def axis_short(idx: int) -> str:
    return f"A{max(0, min(idx, len(AXES) - 1)) + 1}"
