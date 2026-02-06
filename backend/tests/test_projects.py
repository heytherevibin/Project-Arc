"""
Projects Endpoint Tests
"""

import pytest
from unittest.mock import AsyncMock
from fastapi.testclient import TestClient


def test_list_projects_unauthorized(client: TestClient):
    """Test listing projects without authentication."""
    response = client.get("/api/v1/projects")
    assert response.status_code == 401


def test_list_projects_authorized(
    client: TestClient,
    auth_headers: dict,
    mock_neo4j_client,
    test_project: dict,
):
    """Test listing projects with valid authentication."""
    mock_neo4j_client.execute_read.return_value = [{"p": test_project}]
    
    response = client.get("/api/v1/projects", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert "items" in data
    assert "total" in data


def test_create_project_unauthorized(client: TestClient):
    """Test creating project without authentication."""
    response = client.post(
        "/api/v1/projects",
        json={"name": "Test Project", "scope": ["example.com"]},
    )
    assert response.status_code == 401


def test_create_project_missing_fields(client: TestClient, auth_headers: dict):
    """Test creating project with missing required fields."""
    response = client.post(
        "/api/v1/projects",
        headers=auth_headers,
        json={},
    )
    assert response.status_code == 422


def test_create_project_empty_scope(client: TestClient, auth_headers: dict):
    """Test creating project with empty scope."""
    response = client.post(
        "/api/v1/projects",
        headers=auth_headers,
        json={"name": "Test Project", "scope": []},
    )
    assert response.status_code == 422


def test_get_project_unauthorized(client: TestClient):
    """Test getting project without authentication."""
    response = client.get("/api/v1/projects/test-id")
    assert response.status_code == 401


def test_get_project_not_found(
    client: TestClient,
    auth_headers: dict,
    mock_neo4j_client,
):
    """Test getting non-existent project."""
    mock_neo4j_client.execute_read.return_value = []
    
    response = client.get(
        "/api/v1/projects/nonexistent-id",
        headers=auth_headers,
    )
    assert response.status_code == 404


def test_delete_project_unauthorized(client: TestClient):
    """Test deleting project without authentication."""
    response = client.delete("/api/v1/projects/test-id")
    assert response.status_code == 401
