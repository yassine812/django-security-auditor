import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURES = ROOT / "tests" / "fixtures"


@pytest.fixture(scope="module")
def vulnerable_app():
    return str(FIXTURES / "vulnerable_app")


@pytest.fixture(scope="module")
def secure_app():
    return str(FIXTURES / "secure_app")


@pytest.fixture()
def workdir(tmp_path):
    return str(tmp_path / "workdir")
