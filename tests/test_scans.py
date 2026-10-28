"""Tests for Scan endpoints."""


def _create_asset(client, headers):
    resp = client.post("/api/assets", json={
        "name": "Scan Test Asset",
        "asset_type": "application",
        "criticality": "HIGH",
    }, headers=headers)
    return resp.json()["id"]


def test_create_scan(client, analyst_headers):
    asset_id = _create_asset(client, analyst_headers)
    resp = client.post("/api/scans", json={
        "asset_id": asset_id,
        "scan_type": "SOURCE_CODE",
    }, headers=analyst_headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "QUEUED"
    assert data["asset_id"] == asset_id
    assert data["scan_type"] == "SOURCE_CODE"


def test_create_scan_invalid_type(client, analyst_headers):
    asset_id = _create_asset(client, analyst_headers)
    resp = client.post("/api/scans", json={
        "asset_id": asset_id,
        "scan_type": "INVALID_TYPE",
    }, headers=analyst_headers)
    assert resp.status_code == 400


def test_create_scan_nonexistent_asset(client, analyst_headers):
    resp = client.post("/api/scans", json={
        "asset_id": 99999,
        "scan_type": "CERTIFICATE",
    }, headers=analyst_headers)
    assert resp.status_code == 404


def test_list_scans(client, analyst_headers):
    asset_id = _create_asset(client, analyst_headers)
    client.post("/api/scans", json={"asset_id": asset_id, "scan_type": "SOURCE_CODE"}, headers=analyst_headers)
    resp = client.get("/api/scans", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1


def test_get_scan_by_id(client, analyst_headers):
    asset_id = _create_asset(client, analyst_headers)
    create_resp = client.post("/api/scans", json={"asset_id": asset_id, "scan_type": "CERTIFICATE"},
                              headers=analyst_headers)
    scan_id = create_resp.json()["id"]
    resp = client.get(f"/api/scans/{scan_id}", headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json()["id"] == scan_id


def test_start_scan(client, analyst_headers):
    asset_id = _create_asset(client, analyst_headers)
    create_resp = client.post("/api/scans", json={"asset_id": asset_id, "scan_type": "SAMPLE_DATA"},
                              headers=analyst_headers)
    scan_id = create_resp.json()["id"]
    resp = client.post(f"/api/scans/{scan_id}/start", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "COMPLETED"
    assert data["findings_count"] > 0


def test_start_already_running_scan(client, analyst_headers):
    """Starting a COMPLETED scan should return 400."""
    asset_id = _create_asset(client, analyst_headers)
    create_resp = client.post("/api/scans", json={"asset_id": asset_id, "scan_type": "SOURCE_CODE"},
                              headers=analyst_headers)
    scan_id = create_resp.json()["id"]
    client.post(f"/api/scans/{scan_id}/start", headers=analyst_headers)
    # Try starting again
    resp = client.post(f"/api/scans/{scan_id}/start", headers=analyst_headers)
    assert resp.status_code == 400
