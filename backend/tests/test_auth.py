"""
Authentication Endpoint Tests
"""

import pytest
from unittest.mock import AsyncMock
from fastapi.testclient import TestClient


def test_register_missing_fields(client: TestClient):
    """Test registration with missing fields."""
    response = client.post("/api/v1/auth/register", json={})
    assert response.status_code == 422


def test_register_invalid_email(client: TestClient):
    """Test registration with invalid email."""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "not-an-email",
            "password": "password123",
            "name": "Test User",
        },
    )
    assert response.status_code == 422


def test_register_short_password(client: TestClient):
    """Test registration with short password."""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "test@example.com",
            "password": "short",
            "name": "Test User",
        },
    )
    assert response.status_code == 422


def test_login_missing_fields(client: TestClient):
    """Test login with missing fields."""
    response = client.post("/api/v1/auth/login", json={})
    assert response.status_code == 422


def test_login_invalid_credentials(client: TestClient, mock_neo4j_client):
    """Test login with invalid credentials."""
    mock_neo4j_client.execute_read.return_value = []
    
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "nonexistent@example.com",
            "password": "wrongpassword",
        },
    )
    assert response.status_code == 401


def test_refresh_token_missing(client: TestClient):
    """Test refresh with missing token."""
    response = client.post(
        "/api/v1/auth/refresh",
        json={},
    )
    assert response.status_code == 422


def test_refresh_token_invalid(client: TestClient):
    """Test refresh with invalid token."""
    response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "invalid-token"},
    )
    assert response.status_code == 401
