"""Concrete automated security tests (spec 14) and the runner."""
from __future__ import annotations

import urllib.parse

from scanners.base import Evidence, Finding
from security_tests.framework import SecurityTest, TestContext, TestResult

SQL_ERROR_MARKERS = ("syntax error at or near", "sqlite3.OperationalError",
                     "psycopg2.errors", "MySQLdb", "ORA-01756",
                     "Unclosed quotation mark", "django.db.utils.",
                     "OperationalError", "ProgrammingError")
XSS_PAYLOAD = "<dsosec-t7>alert(1)</dsosec-t7>"


class UnauthenticatedAccessTest(SecurityTest):
    id = "AUTH-001"
    requirement_ids = ["REQ-001", "REQ-119"]
    name = "Unauthenticated request to protected endpoints"
    description = "Requests protected endpoints without credentials; expects 401/403/302."
    severity = "High"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        endpoints = [e for e in (ctx.endpoints or [])
                     if e["method"] == "GET" and "{" not in e["path"]
                     and not self.public_looking(e["path"])]
        if not endpoints:
            return self.not_tested("no non-public GET endpoints discovered")
        client = ctx.client()
        bad = []
        checked = 0
        for ep in endpoints[:10]:
            url = ctx.base_url + ep["path"]
            resp = client.get(url)
            checked += 1
            if resp.status == 200 and len(resp.body) > 120:
                bad.append((ep["path"], resp.status))
        if bad:
            paths = ", ".join(p for p, _ in bad[:5])
            return TestResult("FAIL", expected="401/403/302 for anonymous requests",
                              actual=f"HTTP 200 on: {paths}",
                              location={"url": ctx.base_url + bad[0][0],
                                        "status": bad[0][1]})
        return TestResult("PASS", expected="401/403/302 for anonymous requests",
                          actual=f"{checked} endpoints gated correctly")


class VerticalEscalationTest(SecurityTest):
    id = "AUTHZ-V-001"
    requirement_ids = ["REQ-006", "REQ-095", "REQ-121"]
    name = "Vertical privilege escalation (normal user -> admin)"
    description = "A normal user must not reach administrative interfaces."
    severity = "High"
    needs_accounts = True

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        client, info = self.login(ctx, "user")
        if client is None:
            return self.not_tested(info)
        resp = client.get(ctx.base_url + "/admin/")
        if resp.status == 200 and "Django administration" in resp.body:
            return TestResult("FAIL", expected="302/403 for non-staff user on /admin/",
                              actual=f"HTTP {resp.status} with admin content",
                              location={"url": ctx.base_url + "/admin/", "status": resp.status})
        return TestResult("PASS", expected="302/403 for non-staff user on /admin/",
                          actual=f"HTTP {resp.status}", detail=info)


class HorizontalEscalationTest(SecurityTest):
    id = "AUTHZ-H-001"
    requirement_ids = ["REQ-004", "REQ-088", "REQ-120", "REQ-128"]
    name = "Horizontal escalation / IDOR between two users"
    description = "User A requests objects by id; if objects differ per user, User B's " \
                  "session must not retrieve User A's private data."
    severity = "Critical"
    needs_accounts = True

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        details = self.detail_endpoints(ctx)
        if not details:
            return self.not_tested("no detail endpoints discovered")
        client_a, info_a = self.login(ctx, "user_a")
        client_b, info_b = self.login(ctx, "user_b")
        if client_a is None or client_b is None:
            return self.not_tested(f"{info_a}; {info_b}")
        hits = []
        for ep in details[:5]:
            for obj_id in (1, 2, 3):
                path = ep["path"].replace("{id}", str(obj_id)).replace("{pk}", str(obj_id))
                url = ctx.base_url + path
                ra = client_a.get(url)
                rb = client_b.get(url)
                if ra.status == 200 and rb.status == 200 and ra.body != rb.body \
                        and len(ra.body) > 120:
                    hits.append((url, ra.status, rb.status))
        if hits:
            return TestResult("FAIL", expected="403/404 for another user's objects",
                              actual=f"HTTP 200 with differing per-user content at {hits[0][0]}",
                              detail="Both accounts retrieved the same object id with different "
                                     "content - possible shared private data (IDOR).",
                              location={"url": hits[0][0], "status": hits[0][1]})
        return TestResult("PASS", expected="403/404 for another user's objects",
                          actual="no cross-user object retrieval detected")


class ReflectedXSSTest(SecurityTest):
    id = "XSS-001"
    requirement_ids = ["REQ-027", "REQ-122"]
    name = "Reflected XSS probes"
    severity = "High"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        targets = [e for e in (ctx.endpoints or []) if e["method"] == "GET"
                   and "{" not in e["path"]][:10]
        if not targets:
            return self.not_tested("no GET endpoints discovered")
        client = ctx.client()
        for ep in targets:
            url = ctx.base_url + ep["path"] + "?q=" + urllib.parse.quote(XSS_PAYLOAD)
            resp = client.get(url)
            if XSS_PAYLOAD in resp.body:
                return TestResult("FAIL", expected="payload HTML-encoded in output",
                                  actual="payload reflected unencoded",
                                  location={"url": url, "status": resp.status,
                                            "response": resp.body[:300]})
        return TestResult("PASS", expected="payload HTML-encoded in output",
                          actual=f"no reflection across {len(targets)} endpoints")


class SQLInjectionTest(SecurityTest):
    id = "SQLI-001"
    requirement_ids = ["REQ-008", "REQ-123"]
    name = "SQL injection error-based probes"
    severity = "Critical"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        targets = [e for e in (ctx.endpoints or []) if e["method"] == "GET"
                   and "{" not in e["path"]][:10]
        if not targets:
            return self.not_tested("no GET endpoints discovered")
        client = ctx.client()
        payloads = ["'", "' OR '1'='1", "1 UNION SELECT NULL", '";--']
        for ep in targets:
            for p in payloads:
                url = ctx.base_url + ep["path"] + "?id=" + urllib.parse.quote(p)
                resp = client.get(url)
                if any(m in resp.body for m in SQL_ERROR_MARKERS):
                    return TestResult("FAIL", expected="parameterized handling / generic error",
                                      actual="database error disclosed",
                                      location={"url": url, "status": resp.status,
                                                "response": resp.body[:300]})
        return TestResult("PASS", expected="parameterized handling / generic error",
                          actual=f"no SQL error disclosure across {len(targets)} endpoints")


class PathTraversalTest(SecurityTest):
    id = "TRAVERSAL-001"
    requirement_ids = ["REQ-032", "REQ-036", "REQ-125"]
    name = "Path traversal probes"
    severity = "High"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        targets = [e for e in (ctx.endpoints or []) if e["method"] == "GET"
                   and "{" not in e["path"]][:10]
        if not targets:
            return self.not_tested("no GET endpoints discovered")
        client = ctx.client()
        probes = ["?file=..%2f..%2f..%2f..%2fetc%2fpasswd",
                  "?path=..%2f..%2f..%2f..%2fetc%2fpasswd",
                  "?page=..%2f..%2f..%2f..%2fetc%2fpasswd"]
        for ep in targets:
            for probe in probes:
                url = ctx.base_url + ep["path"] + probe
                resp = client.get(url)
                if "root:" in resp.body and "/bin/" in resp.body:
                    return TestResult("FAIL", expected="403/404 for traversal sequences",
                                      actual="filesystem content returned",
                                      location={"url": url, "status": resp.status,
                                                "response": resp.body[:200]})
        return TestResult("PASS", expected="403/404 for traversal sequences",
                          actual="no traversal succeeded")


class OpenRedirectTest(SecurityTest):
    id = "REDIR-001"
    requirement_ids = ["REQ-038", "REQ-081"]
    name = "Open redirect probes (next= parameter)"
    severity = "Medium"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        targets = [e for e in (ctx.endpoints or []) if e["method"] == "GET"
                   and "{" not in e["path"]][:10]
        if not targets:
            return self.not_tested("no GET endpoints discovered")
        client = ctx.client()
        probe = "?next=" + urllib.parse.quote("http://evil.example.com/")
        for ep in targets:
            url = ctx.base_url + ep["path"] + probe
            resp = client.get(url)
            if resp.status in (301, 302) and "evil.example.com" in resp.header("Location"):
                return TestResult("FAIL", expected="external redirect target rejected",
                                  actual=f"redirect to {resp.header('Location')}",
                                  location={"url": url, "status": resp.status})
        return TestResult("PASS", expected="external redirect target rejected",
                          actual="no open redirect detected")


class SSRFTest(SecurityTest):
    id = "SSRF-001"
    requirement_ids = ["REQ-037", "REQ-124"]
    name = "SSRF canary probes"
    severity = "High"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        targets = [e for e in (ctx.endpoints or []) if e["method"] == "GET"
                   and "{" not in e["path"]][:10]
        if not targets:
            return self.not_tested("no GET endpoints discovered")
        client = ctx.client()
        canary = "http://dsosec-canary.invalid/resource"
        for ep in targets:
            for param in ("url", "target", "link", "fetch"):
                url = ctx.base_url + ep["path"] + "?" + param + "=" + \
                    urllib.parse.quote(canary, safe="")
                resp = client.get(url)
                if "dsosec-canary.invalid" in resp.body and any(
                        m in resp.body for m in ("Name or service not known",
                                                 "Temporary failure in name resolution",
                                                 "getaddrinfo failed", "ConnectionError")):
                    return TestResult("FAIL", expected="URL parameters ignored or validated",
                                      actual="server attempted outbound fetch of user URL",
                                      detail="DNS/connection error referencing the canary host "
                                             "indicates a server-side request attempt (SSRF).",
                                      location={"url": url, "status": resp.status,
                                                "response": resp.body[:300]})
        return TestResult("PASS", expected="URL parameters ignored or validated",
                          actual="no SSRF behaviour observed")


class CSRFTest(SecurityTest):
    id = "CSRF-001"
    requirement_ids = ["REQ-009", "REQ-127"]
    name = "State-changing POST without CSRF token"
    severity = "Medium"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        targets = [e for e in (ctx.endpoints or []) if e["method"] == "POST"
                   and "{" not in e["path"] and not self.public_looking(e["path"])][:8]
        if not targets:
            return self.not_tested("no POST endpoints discovered")
        client = ctx.client()
        failures = []
        for ep in targets:
            url = ctx.base_url + ep["path"]
            resp = client.post(url, data=b"x=1",
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
            if resp.status in (200, 201, 302):
                failures.append((ep["path"], resp.status))
        if failures:
            return TestResult("FAIL", expected="403 CSRF error or 401 for anonymous POST",
                              actual=f"accepted without token: {failures[0][0]} "
                                     f"(HTTP {failures[0][1]})",
                              location={"url": ctx.base_url + failures[0][0],
                                        "status": failures[0][1]})
        return TestResult("PASS", expected="403 CSRF error or 401 for anonymous POST",
                          actual=f"{len(targets)} endpoints rejected token-less POST")


class RateLimitTest(SecurityTest):
    id = "RATE-001"
    requirement_ids = ["REQ-012", "REQ-049"]
    name = "Burst of repeated requests (throttling check)"
    severity = "Low"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        login_eps = [e for e in (ctx.endpoints or []) if "login" in e["path"].lower()]
        ep = login_eps[0] if login_eps else ((ctx.endpoints or [{}])[0])
        if not ep.get("path"):
            return self.not_tested("no endpoint available for burst test")
        client = ctx.client()
        url = ctx.base_url + ep["path"]
        codes = [client.get(url).status for _ in range(20)]
        if any(c == 429 for c in codes):
            return TestResult("PASS", expected="429 under burst", actual="429 observed")
        return TestResult("FAIL", expected="429/throttling under burst",
                          actual=f"all {len([c for c in codes if c])} requests served",
                          location={"url": url})


class UploadSecurityTest(SecurityTest):
    id = "UPLOAD-001"
    requirement_ids = ["REQ-033", "REQ-126"]
    name = "Executable-content upload probe"
    severity = "High"
    needs_accounts = True

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        if "uploads" not in (ctx.profile or {}).get("markers", []) and \
                not any("FILES" in str(e) for e in (ctx.endpoints or [])):
            return self.not_tested("no upload endpoints identified")
        return self.not_tested("upload endpoints identified but no documented upload route; "
                               "manual upload test recommended")


ALL_TESTS: list[SecurityTest] = [
    UnauthenticatedAccessTest(), VerticalEscalationTest(), HorizontalEscalationTest(),
    ReflectedXSSTest(), SQLInjectionTest(), PathTraversalTest(), OpenRedirectTest(),
    SSRFTest(), CSRFTest(), RateLimitTest(), UploadSecurityTest(),
]


class TestRunner:
    """Executes all tests and converts results into evidence/findings."""

    def run_all(self, ctx: TestContext) -> tuple[list[dict], list[Evidence], list[Finding]]:
        executions, evidence, findings = [], [], []
        for test in ALL_TESTS:
            if test.needs_runtime and not ctx.base_url:
                res = test.not_tested("no running application instance")
            elif test.needs_accounts and not ctx.accounts:
                res = test.not_tested("no test accounts configured")
            else:
                try:
                    res = test.execute(ctx)
                except Exception as exc:  # noqa: BLE001 - a test must not kill the audit
                    res = TestResult("NOT_TESTED", expected="test executed",
                                     actual="test error", detail=str(exc))
            executions.append({
                "test_id": test.id, "name": test.name, "description": test.description,
                "severity": test.severity, "requirement_ids": test.requirement_ids,
                "status": res.status, "expected": res.expected, "actual": res.actual,
                "detail": res.detail, "location": res.location,
            })
            polarity = {"PASS": "ok", "FAIL": "vuln"}.get(res.status)
            if polarity:
                ev = Evidence(
                    source="automated", rule_id=f"TEST-{test.id}", polarity=polarity,
                    summary=f"{test.name}: {res.actual}",
                    location=res.location or {}, requirement_ids=list(test.requirement_ids))
                evidence.append(ev)
                if res.status == "FAIL":
                    findings.append(Finding(
                        title=f"[TEST-{test.id}] {test.name}",
                        description=f"Expected: {res.expected}. Actual: {res.actual}. "
                                    f"{res.detail}".strip(),
                        severity=test.severity, confidence="Confirmed",
                        category="Automated Security Test",
                        cwe=["CWE-20"], owasp="A04:2021",
                        requirement_ids=list(test.requirement_ids), sources=["automated"],
                        evidence_ids=[ev.id],
                        endpoint=(res.location or {}).get("url"),
                        response=(res.location or {}).get("response"),
                        proof=res.actual,
                        remediation="Fix the failing control and run a retest.",
                        dedup_key=f"test:{test.id}:{(res.location or {}).get('url', '')}"))
        return executions, evidence, findings
