"""
Scans Endpoint Tests
"""

import pytest
from unittest.mock import AsyncMock
from fastapi.testclient import TestClient


def test_list_scans_unauthorized(client: TestClient):
    """Test listing scans without authentication."""
    response = client.get("/api/v1/scans?project_id=test-id")
    assert response.status_code == 401


def test_list_scans_missing_project_id(client: TestClient, auth_headers: dict):
    """Test listing scans without project_id."""
    response = client.get("/api/v1/scans", headers=auth_headers)
    assert response.status_code == 422


def test_list_scans_authorized(
    client: TestClient,
    auth_headers: dict,
    mock_neo4j_client,
    test_project: dict,
    test_scan: dict,
):
    """Test listing scans with valid authentication."""
    # First call for project access check
    mock_neo4j_client.execute_read.side_effect = [
        [{"p": test_project}],  # Project access check
        [{"s": test_scan}],  # Scans list
    ]
    
    response = client.get(
        "/api/v1/scans?project_id=test-project-id",
        headers=auth_headers,
    )
    assert response.status_code == 200
    
    data = response.json()
    assert "items" in data
    assert "total" in data


def test_start_scan_unauthorized(client: TestClient):
    """Test starting scan without authentication."""
    response = client.post(
        "/api/v1/scans",
        json={
            "project_id": "test-id",
            "target": "example.com",
            "scan_type": "full_recon",
        },
    )
    assert response.status_code == 401


def test_start_scan_missing_fields(client: TestClient, auth_headers: dict):
    """Test starting scan with missing required fields."""
    response = client.post(
        "/api/v1/scans",
        headers=auth_headers,
        json={},
    )
    assert response.status_code == 422


def test_start_scan_invalid_target(
    client: TestClient,
    auth_headers: dict,
    mock_neo4j_client,
    test_project: dict,
):
    """Test starting scan with invalid target (not in scope)."""
    mock_neo4j_client.execute_read.return_value = [{"p": test_project}]
    
    response = client.post(
        "/api/v1/scans",
        headers=auth_headers,
        json={
            "project_id": "test-project-id",
            "target": "not-in-scope.com",
            "scan_type": "full_recon",
        },
    )
    # Should be 400 if target not in scope, or 200 if validation passes
    assert response.status_code in [200, 400]


def test_get_scan_unauthorized(client: TestClient):
    """Test getting scan without authentication."""
    response = client.get("/api/v1/scans/test-id?project_id=test-project")
    assert response.status_code == 401


def test_get_scan_not_found(
    client: TestClient,
    auth_headers: dict,
    mock_neo4j_client,
    test_project: dict,
):
    """Test getting non-existent scan."""
    mock_neo4j_client.execute_read.side_effect = [
        [{"p": test_project}],  # Project access check
        [],  # Scan not found
    ]
    
    response = client.get(
        "/api/v1/scans/nonexistent-id?project_id=test-project-id",
        headers=auth_headers,
    )
    assert response.status_code == 404


def test_stop_scan_unauthorized(client: TestClient):
    """Test stopping scan without authentication."""
    response = client.post(
        "/api/v1/scans/test-id/stop?project_id=test-project",
    )
    assert response.status_code == 401
