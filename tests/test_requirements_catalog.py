"""The 137-requirement catalogue is a validated first-class dataset (spec 6, 40)."""
import yaml

from apps.requirements_engine.loader import (DEFAULT_MAPPING_PATH,
                                             DEFAULT_REQUIREMENTS_PATH,
                                             load_mapping, load_requirements)
from tools.reqcommon import AUTOMATION_LEVELS, CATEGORIES, SEVERITIES


def test_catalogue_has_137_requirements():
    assert len(load_requirements()) == 137


def test_ids_are_sequential():
    reqs = load_requirements()
    assert reqs[0].id == "REQ-001"
    assert reqs[-1].id == "REQ-137"


def test_all_fields_present():
    for r in load_requirements():
        assert r.name and r.description and r.remediation
        assert r.category in CATEGORIES
        assert r.severity in SEVERITIES
        assert r.automation_level in AUTOMATION_LEVELS
        assert r.verification_method, f"{r.id} has no verification method"


def test_all_26_categories_used():
    used = {r.category for r in load_requirements()}
    assert len(used) == 26
    assert used == set(CATEGORIES)


def test_automation_level_examples_from_spec():
    reqs = {r.id: r for r in load_requirements()}
    assert reqs["REQ-015"].automation_level == "FULLY_AUTOMATED"
    assert reqs["REQ-004"].automation_level == "PARTIALLY_AUTOMATED"
    assert reqs["REQ-043"].automation_level == "MANUAL"
    assert reqs["REQ-101"].automation_level == "PARTIALLY_AUTOMATED"


def test_mapping_covers_all_requirements():
    mapping = load_mapping()
    reqs = load_requirements()
    assert set(mapping.keys()) == {r.id for r in reqs}


def test_mapping_references_known_check_families():
    mapping = load_mapping()
    for rid, m in mapping.items():
        for family in ("sast", "configuration", "dependencies", "network", "dast", "automated"):
            assert isinstance(m.get(family, []), list), f"{rid}.{family}"


def test_yaml_files_are_valid():
    data = yaml.safe_load(DEFAULT_REQUIREMENTS_PATH.read_text())
    assert len(data) == 137
    mapping = yaml.safe_load(DEFAULT_MAPPING_PATH.read_text())
    assert len(mapping) == 137


def test_spec_examples_present():
    reqs = {r.id: r for r in load_requirements()}
    assert "Secrets" in reqs["REQ-013"].category
    assert "SAST" not in reqs["REQ-013"].verification_method  # sast is the method name
    assert "sast" in reqs["REQ-013"].verification_method
    assert "dast" in reqs["REQ-004"].verification_method
    assert "network" in reqs["REQ-107"].verification_method


def test_every_requirement_has_cwe_or_is_process():
    for r in load_requirements():
        # process/meta requirements may have no CWE; every requirement maps to OWASP
        assert r.owasp, f"{r.id} lacks OWASP"
        if r.category not in ("Security Process", "Testing"):
            assert r.cwe, f"{r.id} lacks CWE"


def test_technical_requirements_have_cwe():
    reqs = {r.id: r for r in load_requirements()}
    for rid in ("REQ-013", "REQ-015", "REQ-004", "REQ-107", "REQ-037"):
        assert reqs[rid].cwe


def test_testing_requirements_map_to_tests():
    reqs = {r.id: r for r in load_requirements()}
    for rid in ("REQ-119", "REQ-120", "REQ-121", "REQ-122", "REQ-123",
                "REQ-124", "REQ-125", "REQ-126", "REQ-127", "REQ-128"):
        assert reqs[rid].scanner_mapping["automated"], f"{rid} has no test definition"
