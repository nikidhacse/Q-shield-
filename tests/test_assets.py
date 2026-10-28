"""Tests for Asset CRUD endpoints."""


def _create_asset(client, headers, name="Test Server", asset_type="server", criticality="HIGH"):
    return client.post("/api/assets", json={
        "name": name,
        "asset_type": asset_type,
        "environment": "production",
        "criticality": criticality,
        "description": "A test asset",
        "location": "test-server.internal",
    }, headers=headers)


def test_create_asset_as_analyst(client, analyst_headers):
    resp = _create_asset(client, analyst_headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Test Server"
    assert data["criticality"] == "HIGH"
    assert data["asset_type"] == "server"


def test_create_asset_as_viewer_forbidden(client, client_viewer=None, auth_headers=None):
    """Viewers should not be able to create assets."""
    # Register a viewer
    from fastapi.testclient import TestClient
    client.post("/api/auth/register", json={
        "email": "view2@test.com", "username": "view2",
        "password": "ViewPass99", "role": "viewer",
    })
    resp_login = client.post("/api/auth/login", json={
        "email": "view2@test.com", "password": "ViewPass99",
    })
    viewer_token = resp_login.json()["access_token"]
    resp = _create_asset(client, {"Authorization": f"Bearer {viewer_token}"})
    assert resp.status_code == 403


def test_list_assets(client, analyst_headers):
    _create_asset(client, analyst_headers, "Asset A")
    _create_asset(client, analyst_headers, "Asset B")
    resp = client.get("/api/assets", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 2
    assert isinstance(data["assets"], list)


def test_get_asset_by_id(client, analyst_headers):
    create_resp = _create_asset(client, analyst_headers)
    asset_id = create_resp.json()["id"]
    resp = client.get(f"/api/assets/{asset_id}", headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json()["id"] == asset_id


def test_get_asset_not_found(client, analyst_headers):
    resp = client.get("/api/assets/99999", headers=analyst_headers)
    assert resp.status_code == 404


def test_update_asset(client, analyst_headers):
    create_resp = _create_asset(client, analyst_headers)
    asset_id = create_resp.json()["id"]
    resp = client.put(f"/api/assets/{asset_id}", json={
        "description": "Updated description",
        "criticality": "CRITICAL",
    }, headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json()["criticality"] == "CRITICAL"
    assert resp.json()["description"] == "Updated description"


def test_delete_asset_as_admin(client, auth_headers, analyst_headers):
    create_resp = _create_asset(client, analyst_headers)
    asset_id = create_resp.json()["id"]
    resp = client.delete(f"/api/assets/{asset_id}", headers=auth_headers)
    assert resp.status_code == 204
    # Verify deleted
    get_resp = client.get(f"/api/assets/{asset_id}", headers=analyst_headers)
    assert get_resp.status_code == 404


def test_delete_asset_as_analyst_forbidden(client, analyst_headers):
    create_resp = _create_asset(client, analyst_headers)
    asset_id = create_resp.json()["id"]
    resp = client.delete(f"/api/assets/{asset_id}", headers=analyst_headers)
    assert resp.status_code == 403


def test_filter_assets_by_criticality(client, analyst_headers):
    _create_asset(client, analyst_headers, "Critical Asset", criticality="CRITICAL")
    _create_asset(client, analyst_headers, "Low Asset", criticality="LOW")
    resp = client.get("/api/assets?criticality=CRITICAL", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert all(a["criticality"] == "CRITICAL" for a in data["assets"])
