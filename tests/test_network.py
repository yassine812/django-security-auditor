"""Network scanner tests (spec 11) - authorization gating + live local scans."""
import socket
import threading

import pytest

from scanners.base import AuditContext
from scanners.network.scanner import COMMON_PORTS, NetworkScanner


@pytest.fixture()
def open_port():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def acceptor():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except OSError:
                break
    t = threading.Thread(target=acceptor, daemon=True)
    t.start()
    yield port
    stop.set()
    srv.close()


def ctx_for(target="127.0.0.1", authorized=True, expected=(), scan_ports=None):
    config = {"network": {"authorized_targets": [target],
                          "expected_open_ports": list(expected)}}
    if scan_ports:
        config["network"]["scan_ports"] = list(scan_ports)
    return AuditContext(source_dir=".", config=config, authorization_confirmed=authorized)


def test_scan_refused_without_authorization():
    r = NetworkScanner().safe_run(ctx_for(authorized=False))
    assert r.status == "SKIPPED"
    assert "authorization" in r.error


def test_scan_refuses_unlisted_public_target():
    config = {"network": {"authorized_targets": ["203.0.113.9"]}}
    ctx = AuditContext(source_dir=".", config=config, authorization_confirmed=True)
    r = NetworkScanner().safe_run(ctx)
    assert any("refused" in e.summary for e in r.evidence)
    assert r.status == "SKIPPED"


def test_python_scan_detects_open_port(open_port):
    scanner = NetworkScanner()
    scanner.scan_ports = [open_port]
    ports = scanner._python_scan("127.0.0.1")
    assert ports[0]["state"] == "open"
    assert ports[0]["port"] == open_port


def test_closed_ports_reported_closed(open_port):
    scanner = NetworkScanner()
    scanner.scan_ports = [open_port + 1 if open_port < 65535 else open_port - 1]
    ports = scanner._python_scan("127.0.0.1")
    assert ports[0]["state"] in ("closed", "filtered")


def test_banner_guess_ssh():
    assert NetworkScanner._guess_version(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3") \
        == "SSH-2.0-OpenSSH_8.9p1"


def test_banner_guess_http():
    v = NetworkScanner._guess_version(80, "HTTP/1.1 200 OK\r\nServer: WSGIServer/0.2 CPython")
    assert "WSGIServer" in v


def test_unexpected_open_port_flagged(open_port):
    r = NetworkScanner().safe_run(ctx_for(expected=[], scan_ports=[open_port]))
    assert any("PORT-EXTRA-001" in f.dedup_key and f.dedup_key.endswith(f":{open_port}")
               for f in r.findings)


def test_expected_port_not_flagged_unexpected(open_port):
    r = NetworkScanner().safe_run(ctx_for(expected=[open_port], scan_ports=[open_port]))
    assert not any("PORT-EXTRA-001" in f.dedup_key for f in r.findings)


def test_inventory_evidence_recorded(open_port):
    r = NetworkScanner().safe_run(ctx_for(expected=[open_port], scan_ports=[open_port]))
    assert any(e.rule_id == "SVC-VERSION-001" for e in r.evidence)


def test_findings_map_to_requirements():
    r = NetworkScanner()
    from scanners.base import ScanResult
    res = ScanResult(scanner="network")
    r._finding(res, "PORT-DB-001", "High", "PostgreSQL exposed", "db exposed",
               ["REQ-107"], "127.0.0.1", 5432, "PostgreSQL", "16.1")
    assert res.findings[0].requirement_ids == ["REQ-107"]
    assert res.findings[0].severity == "High"
