
import pytest, os, json
# Ensure keys exist for tests
@pytest.fixture(scope="session", autouse=True)
def _keys():
    os.system("python tools/gen_keys.py > /dev/null 2>&1")
