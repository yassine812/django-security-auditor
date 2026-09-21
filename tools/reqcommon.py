"""Helpers for generating the 137-requirement catalogue and mapping files.

The requirement catalogue is *data*, not code: it lives in
``requirements/django_137_requirements.yml``.  The Python tables in this
directory are the single source of truth from which the YAML is generated so
that adding a new requirement is a one-line, reviewable change.
"""
from __future__ import annotations

CATEGORIES = [
    "Authentication", "Authorization", "Multi-tenant", "Input Validation",
    "Database", "HTTP/Web", "Session", "XSS", "CSRF", "File Security",
    "Secrets", "Cryptography", "Configuration", "API", "Logging",
    "Dependencies", "Transport", "Headers", "Business Logic", "Availability",
    "Privacy", "Infrastructure", "Network", "Information Disclosure",
    "Security Process", "Testing",
]

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]

AUTOMATION_LEVELS = [
    "FULLY_AUTOMATED", "PARTIALLY_AUTOMATED", "MANUAL", "NOT_AUTOMATABLE",
]

VERIFICATION_METHODS = [
    "sast", "configuration", "dependencies", "network", "dast",
    "automated", "manual", "internal",
]


def R(rid, name, category, severity, *, desc, fix, ver, auto, cwe=(),
      owasp="", sast=(), conf=(), dep=(), net=(), dast=(), tests=(),
      manual=False):
    """Build one requirement record.

    ``sast/conf/dep/net/dast/tests`` hold scanner / check rule ids that
    produce evidence for the requirement (see rules/requirement_mapping.yml).
    """
    assert category in CATEGORIES, f"{rid}: bad category {category}"
    assert severity in SEVERITIES, f"{rid}: bad severity {severity}"
    assert auto in AUTOMATION_LEVELS, f"{rid}: bad automation {auto}"
    for v in ver:
        assert v in VERIFICATION_METHODS, f"{rid}: bad verification {v}"
    return {
        "id": rid,
        "name": name,
        "category": category,
        "severity": severity,
        "description": desc,
        "remediation": fix,
        "verification": list(ver),
        "automation_level": auto,
        "cwe": list(cwe),
        "owasp": owasp,
        "scanner_mapping": {
            "sast": list(sast),
            "configuration": list(conf),
            "dependencies": list(dep),
            "network": list(net),
            "dast": list(dast),
            "automated": list(tests),
        },
        "manual_review": bool(manual) or "manual" in ver,
    }
