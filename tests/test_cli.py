"""CLI acceptance tests (spec 31, 45)."""
import json

import pytest

from apps.cli import build_parser, main


def test_parser_commands_exist():
    parser = build_parser()
    arg_map = {
        "full": ["./proj"], "scan": ["./proj"], "github": ["https://github.com/o/r"],
        "zip": ["a.zip"], "sast": ["./proj"], "deps": ["./proj"],
        "requirements": ["./proj"], "network": ["127.0.0.1"],
        "dast": ["http://127.0.0.1:8000"], "report": ["audit-1"], "list": [],
        "show": ["audit-1"], "retest": ["audit-1", "./proj"], "init": [], "serve": [],
    }
    for cmd, extra in arg_map.items():
        args = parser.parse_args([cmd, *extra])
        assert args.command == cmd


def test_sast_command(capsys, vulnerable_app):
    rc = main(["--workdir", "/tmp/wd-x", "sast", vulnerable_app])
    assert rc == 0
    out = capsys.readouterr().out
    assert "total findings:" in out
    assert "Dynamic code execution" in out


def test_deps_command(capsys, vulnerable_app):
    rc = main(["--workdir", "/tmp/wd-x", "deps", vulnerable_app])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CVE-2024-45230" in out


def test_requirements_command(capsys, vulnerable_app):
    rc = main(["--workdir", "/tmp/wd-x", "requirements", vulnerable_app])
    assert rc == 0
    out = capsys.readouterr().out
    assert "requirements evaluated statically" in out


def test_init_command(tmp_path, capsys):
    target = tmp_path / "security-audit.yml"
    rc = main(["init", "--output", str(target)])
    assert rc == 0
    assert target.exists()
    import yaml
    data = yaml.safe_load(target.read_text())
    assert data["scanning"]["sast"] is True


def test_full_command_e2e(tmp_path, capsys, vulnerable_app):
    import yaml
    cfg = tmp_path / "cfg.yml"
    cfg.write_text(yaml.safe_dump({"scanning": {"dast": False},
                                   "network": {"authorized_targets": ["127.0.0.1"],
                                               "scan_ports": [1]}}))
    rc = main(["--workdir", str(tmp_path / "wd"), "--config", str(cfg),
               "full", vulnerable_app, "--yes"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "AUDIT COMPLETE" in out
    assert "Requirements:   137" in out.replace("Requirements:", "Requirements:  ") or \
           "Requirements: 137" in out
    assert "PASS" in out and "FAIL" in out
    assert "Top findings:" in out


def test_list_and_show_commands(tmp_path, capsys, vulnerable_app):
    import yaml
    cfg = tmp_path / "cfg.yml"
    cfg.write_text(yaml.safe_dump({"scanning": {"dast": False},
                                   "network": {"scan_ports": [1],
                                               "authorized_targets": ["127.0.0.1"]}}))
    main(["--workdir", str(tmp_path / "wd"), "--config", str(cfg),
          "full", vulnerable_app, "--yes"])
    capsys.readouterr()
    rc = main(["--workdir", str(tmp_path / "wd"), "list"])
    out = capsys.readouterr().out
    assert "audit-" in out
    audit_id = out.strip().splitlines()[0].split()[0]
    rc = main(["--workdir", str(tmp_path / "wd"), "show", audit_id])
    assert rc == 0
    assert "AUDIT COMPLETE" in capsys.readouterr().out
