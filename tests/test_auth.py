"""Tests for Authentication endpoints: register, login, and /me."""


def test_register_success(client):
    resp = client.post("/api/auth/register", json={
        "email": "newuser@test.com",
        "username": "newuser",
        "password": "SecurePass99",
        "role": "viewer",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == "newuser@test.com"
    assert data["username"] == "newuser"
    assert data["role"] == "viewer"
    assert "hashed_password" not in data


def test_register_duplicate_email(client, admin_user):
    resp = client.post("/api/auth/register", json={
        "email": "admin@test.com",
        "username": "otheradmin",
        "password": "AnotherPass99",
        "role": "viewer",
    })
    assert resp.status_code == 400
    assert "already registered" in resp.json()["detail"]


def test_register_duplicate_username(client, admin_user):
    resp = client.post("/api/auth/register", json={
        "email": "unique@test.com",
        "username": "testadmin",   # Same username as admin_user fixture
        "password": "AnotherPass99",
        "role": "viewer",
    })
    assert resp.status_code == 400
    assert "already taken" in resp.json()["detail"]


def test_register_weak_password(client):
    resp = client.post("/api/auth/register", json={
        "email": "weak@test.com",
        "username": "weakuser",
        "password": "123",
        "role": "viewer",
    })
    assert resp.status_code == 422   # Pydantic validation error


def test_login_success(client, admin_user):
    resp = client.post("/api/auth/login", json={
        "email": "admin@test.com",
        "password": "testpass123",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0


def test_login_wrong_password(client, admin_user):
    resp = client.post("/api/auth/login", json={
        "email": "admin@test.com",
        "password": "wrongpassword",
    })
    assert resp.status_code == 401


def test_login_nonexistent_user(client):
    resp = client.post("/api/auth/login", json={
        "email": "nobody@test.com",
        "password": "somepassword",
    })
    assert resp.status_code == 401


def test_get_me_authenticated(client, auth_headers):
    resp = client.get("/api/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == "admin@test.com"
    assert data["role"] == "admin"


def test_get_me_unauthenticated(client):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401


def test_get_me_invalid_token(client):
    resp = client.get("/api/auth/me", headers={"Authorization": "Bearer invalid.token.here"})
    assert resp.status_code == 401
