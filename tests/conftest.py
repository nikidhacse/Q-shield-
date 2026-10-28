"""
Pytest configuration and shared fixtures for Q-Shield test suite.
Uses an in-memory SQLite database to keep tests fast and isolated.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.core.security import hash_password
from app.main import app
from app.models.user import User, UserRole

# ---------------------------------------------------------------------------
# Test database (in-memory SQLite – no PostgreSQL required for unit tests)
# ---------------------------------------------------------------------------
TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="function")
def db():
    """Create all tables, yield a session, then drop all tables after each test."""
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db):
    """FastAPI TestClient with the DB dependency overridden to use the test DB."""
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def admin_user(db):
    """Create and return an admin user in the test DB."""
    user = User(
        email="admin@test.com",
        username="testadmin",
        full_name="Test Admin",
        hashed_password=hash_password("testpass123"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def analyst_user(db):
    """Create and return a security analyst user in the test DB."""
    user = User(
        email="analyst@test.com",
        username="testanalyst",
        full_name="Test Analyst",
        hashed_password=hash_password("testpass123"),
        role=UserRole.SECURITY_ANALYST,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def admin_token(client, admin_user):
    """Return a valid JWT access token for the admin user."""
    resp = client.post("/api/auth/login", json={
        "email": "admin@test.com",
        "password": "testpass123",
    })
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture
def analyst_token(client, analyst_user):
    """Return a valid JWT access token for the analyst user."""
    resp = client.post("/api/auth/login", json={
        "email": "analyst@test.com",
        "password": "testpass123",
    })
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture
def auth_headers(admin_token):
    """Return Authorization headers with the admin token."""
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def analyst_headers(analyst_token):
    """Return Authorization headers with the analyst token."""
    return {"Authorization": f"Bearer {analyst_token}"}
