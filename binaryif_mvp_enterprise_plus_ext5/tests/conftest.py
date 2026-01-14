import pytest, os, json, sys
from fastapi.testclient import TestClient

# Ensure the app module is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Change to project directory
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Generate keys once at module load time
os.system("PYTHONPATH=. python tools/gen_keys.py > /dev/null 2>&1")

# Initialize app at module load time
from app.main import app, _startup
from app.db import init_db, reset_db

init_db()
_startup()

# Reset database before each test for isolation
@pytest.fixture(autouse=True)
def _reset_db():
    reset_db()
    yield
