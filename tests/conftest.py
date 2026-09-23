"""
conftest.py
Shared pytest fixtures: an isolated test database so tests never touch
data/monitor.db, plus a FastAPI TestClient fixture.
"""

import os
import tempfile
import pytest

# IMPORTANT: set DATABASE_URL before any src.storage import happens,
# so the test suite uses its own throwaway SQLite file, never the real one.
_test_db_fd, _test_db_path = tempfile.mkstemp(suffix=".db")
os.environ["DATABASE_URL"] = f"sqlite:///{_test_db_path}"


@pytest.fixture(scope="session", autouse=True)
def _setup_test_database():
    """Runs once per test session: creates schema in the temp DB via Alembic."""
    from alembic import command
    from alembic.config import Config
    from src.storage.database import PROJECT_ROOT

    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "alembic"))
    command.upgrade(cfg, "head")

    yield

    from src.storage.database import engine
    engine.dispose()  # release SQLite's file lock (Windows keeps it open otherwise)

    os.close(_test_db_fd)
    if os.path.exists(_test_db_path):
        try:
            os.remove(_test_db_path)
        except PermissionError:
            pass  # harmless leftover temp file; OS will clean it up eventually


@pytest.fixture(autouse=True)
def _clean_tables():
    """Runs before every test: wipes all rows so tests don't interfere with each other."""
    from src.storage.database import SessionLocal
    from src.storage.models import Candidate, CandidateEvent, Webhook

    session = SessionLocal()
    session.query(CandidateEvent).delete()
    session.query(Candidate).delete()
    session.query(Webhook).delete()
    session.commit()
    session.close()
    yield


@pytest.fixture
def api_client():
    """FastAPI TestClient for endpoint tests."""
    from fastapi.testclient import TestClient
    from api.main import app

    return TestClient(app)
