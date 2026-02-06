"""
Health Endpoint Tests
"""

import pytest
from fastapi.testclient import TestClient


def test_health_endpoint(client: TestClient):
    """Test /health endpoint returns system status."""
    response = client.get("/health")
    assert response.status_code == 200
    
    data = response.json()
    assert "status" in data
    assert "app_version" in data
    assert "environment" in data


def test_liveness_endpoint(client: TestClient):
    """Test /live endpoint for Kubernetes liveness probe."""
    response = client.get("/live")
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "alive"


def test_readiness_endpoint(client: TestClient):
    """Test /ready endpoint for Kubernetes readiness probe."""
    response = client.get("/ready")
    # May return 200 or 503 depending on Neo4j connection
    assert response.status_code in [200, 503]
    
    data = response.json()
    assert "status" in data
    assert "checks" in data
