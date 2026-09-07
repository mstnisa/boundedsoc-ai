"""
Shared pytest fixtures. Uses a real PostgreSQL test database (DATABASE_URL
override via TEST_DATABASE_URL / a soc_workbench_test DB) rather than
mocking the ORM — SQLAlchemy + Postgres-specific types (JSONB, UUID, Enum)
are part of what we're testing. Tables are created/dropped per test module
via Alembic-equivalent metadata create_all/drop_all for speed; migrations
themselves are exercised separately (see tests/integration/test_migrations.py).
"""

import os

os.environ.setdefault(
    "DATABASE_URL",
    os.environ.get(
        "TEST_DATABASE_URL",
        "postgresql+psycopg2://soc_admin:soc_admin_dev@localhost:5432/soc_workbench_test",
    ),
)
os.environ.setdefault("LLM_PROVIDER", "mock")
os.environ.setdefault("TI_USE_LIVE_PROVIDERS", "false")
os.environ.setdefault("AUTH_SINGLE_USER_MODE", "true")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.db.all_models import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app  # noqa: E402

settings = get_settings()
engine = create_engine(settings.database_url, future=True)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)


@pytest.fixture(scope="session", autouse=True)
def _create_schema():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def _clean_tables():
    """Truncate all tables between tests so each test starts from empty state."""
    yield
    with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())


@pytest.fixture
def db_session():
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    def _override_get_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
