"""Tests for the real-world-deployment upgrades:
nested manage.py discovery, venv dependency inventory, exact fix examples."""
from pathlib import Path

from apps.reports.fix_examples import fix_for
from scanners.dependencies.scanner import _venv_inventory
from scanners.dast.sandbox import _find_manage_py


def test_find_manage_py_nested(tmp_path: Path):
    proj = tmp_path / "repo" / "Module_Audit"
    proj.mkdir(parents=True)
    (proj / "manage.py").write_text("#!/usr/bin/env python\n", encoding="utf-8")
    (proj / "Module_Audit").mkdir()
    (proj / "Module_Audit" / "settings.py").write_text("X=1\n", encoding="utf-8")
    found = _find_manage_py(tmp_path / "repo")
    assert found == proj


def test_find_manage_py_prefers_shallowest(tmp_path: Path):
    (tmp_path / "manage.py").write_text("x\n", encoding="utf-8")
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    (deep / "manage.py").write_text("x\n", encoding="utf-8")
    assert _find_manage_py(tmp_path) == tmp_path


def test_find_manage_py_skips_venvs(tmp_path: Path):
    venv = tmp_path / ".venv" / "proj"
    venv.mkdir(parents=True)
    (venv / "manage.py").write_text("x\n", encoding="utf-8")
    assert _find_manage_py(tmp_path) is None


def test_venv_inventory(tmp_path: Path):
    sp = tmp_path / "venv" / "lib" / "python3.12" / "site-packages"
    di = sp / "django-4.2.0.dist-info"
    di.mkdir(parents=True)
    (di / "METADATA").write_text("Metadata-Version: 2.1\nName: Django\nVersion: 4.2\n\n",
                                 encoding="utf-8")
    deps, sources = _venv_inventory(tmp_path)
    assert deps and deps[0]["name"] == "Django"
    assert deps[0]["specifier"] == "==4.2"
    assert "installed environment inventory" in sources[0]


def test_venv_inventory_windows_layout(tmp_path: Path):
    sp = tmp_path / ".venv" / "Lib" / "site-packages"
    di = sp / "requests-2.31.0.dist-info"
    di.mkdir(parents=True)
    (di / "METADATA").write_text("Name: requests\nVersion: 2.31.0\n\n", encoding="utf-8")
    deps, _ = _venv_inventory(tmp_path)
    assert any(d["name"] == "requests" for d in deps)


def test_fix_examples_specific():
    fx = fix_for({"title": "Mass assignment via **request.data"})
    assert "serializer" in fx["after"]
    fx = fix_for({"title": "Insecure Django setting: DEBUG"})
    assert "DJANGO_DEBUG" in fx["after"]
    fx = fix_for({"title": "Dynamic SQL via cursor.execute"})
    assert "%s" in fx["after"] and "ORM" in fx["after"]


def test_fix_examples_fallback():
    fx = fix_for({"title": "Something brand new"})
    assert fx["after"].startswith("Review the flagged code")
