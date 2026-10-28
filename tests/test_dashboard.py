"""Tests for Dashboard and Reports endpoints."""


def test_dashboard_overview_structure(client, analyst_headers):
    """Verify the dashboard returns the exact structure expected by the frontend."""
    resp = client.get("/api/dashboard/overview", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()

    required_keys = [
        "total_assets",
        "scanned_assets",
        "critical_assets",
        "high_risk_assets",
        "crypto_findings",
        "quantum_vulnerable_assets",
        "migration_in_progress",
        "risk_distribution",
        "top_priority_assets",
    ]
    for key in required_keys:
        assert key in data, f"Missing key: {key}"

    # risk_distribution should have the four levels
    assert set(data["risk_distribution"].keys()) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    # All counts should be non-negative integers
    for key in ["total_assets", "scanned_assets", "critical_assets", "high_risk_assets",
                "crypto_findings", "quantum_vulnerable_assets", "migration_in_progress"]:
        assert isinstance(data[key], int)
        assert data[key] >= 0


def test_dashboard_unauthenticated(client):
    resp = client.get("/api/dashboard/overview")
    assert resp.status_code == 401


def test_reports_summary_structure(client, analyst_headers):
    resp = client.get("/api/reports/summary", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_assets" in data
    assert "risk_distribution" in data
    assert "total_crypto_findings" in data
    assert "top_algorithms_detected" in data


def test_dashboard_reflects_real_data(client, analyst_headers):
    """Create an asset and verify the dashboard count increases."""
    initial = client.get("/api/dashboard/overview", headers=analyst_headers).json()
    initial_count = initial["total_assets"]

    client.post("/api/assets", json={
        "name": "Dashboard Test Asset",
        "asset_type": "server",
        "criticality": "CRITICAL",
    }, headers=analyst_headers)

    updated = client.get("/api/dashboard/overview", headers=analyst_headers).json()
    assert updated["total_assets"] == initial_count + 1
    assert updated["critical_assets"] >= 1
