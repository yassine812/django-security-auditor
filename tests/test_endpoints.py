"""Endpoint discovery (spec 15)."""
from scanners.dast.endpoints import discover_endpoints


def test_vulnerable_app_endpoints(vulnerable_app):
    eps = discover_endpoints(vulnerable_app)
    paths = {e["path"] for e in eps}
    assert "/admin/" in paths
    assert "/api/documents/" in paths
    assert "/api/documents/{id}/" in paths
    assert any(p.startswith("/api/search") for p in paths)


def test_router_detail_methods(vulnerable_app):
    eps = discover_endpoints(vulnerable_app)
    detail_methods = {e["method"] for e in eps if e["path"] == "/api/documents/{id}/"}
    assert {"GET", "PUT", "PATCH", "DELETE"} <= detail_methods


def test_secure_app_endpoints(secure_app):
    eps = discover_endpoints(secure_app)
    paths = {e["path"] for e in eps}
    assert "/api/notes/" in paths
    assert "/api/notes/{id}/" in paths


def test_endpoint_records_source_file(vulnerable_app):
    eps = discover_endpoints(vulnerable_app)
    assert all(e["source_file"].endswith("urls.py") for e in eps)


def test_no_duplicate_method_path_pairs(vulnerable_app):
    eps = discover_endpoints(vulnerable_app)
    pairs = [(e["method"], e["path"]) for e in eps]
    assert len(pairs) == len(set(pairs))


def test_missing_dir_returns_empty(tmp_path):
    assert discover_endpoints(str(tmp_path)) == []


def test_admin_marked_with_permission(vulnerable_app):
    eps = discover_endpoints(vulnerable_app)
    admin = [e for e in eps if e["path"] == "/admin/"]
    assert admin and admin[0]["permission"] == "is_staff"
