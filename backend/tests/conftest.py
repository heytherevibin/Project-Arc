"""
Pytest Configuration and Fixtures

Provides test fixtures for API testing.
"""

import os
from typing import AsyncIterator, Generator
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient

# Set test environment before importing app
os.environ["APP_ENV"] = "development"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-minimum-32-characters-long"
os.environ["NEO4J_PASSWORD"] = "test-password"


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    """Specify async backend for pytest-asyncio."""
    return "asyncio"


@pytest.fixture
def mock_neo4j_client() -> MagicMock:
    """Create a mock Neo4j client."""
    mock = MagicMock()
    mock.execute_read = AsyncMock(return_value=[])
    mock.execute_write = AsyncMock(return_value=[])
    mock.health_check = AsyncMock(return_value=True)
    return mock


@pytest.fixture
def app(mock_neo4j_client: MagicMock) -> Generator:
    """Create test application with mocked dependencies."""
    from unittest.mock import patch
    
    # Patch Neo4j client before importing app
    with patch("graph.client.get_neo4j_client", return_value=mock_neo4j_client):
        with patch("graph.client.init_neo4j", new_callable=AsyncMock):
            with patch("graph.schema_init.init_schema", new_callable=AsyncMock):
                from api.main import app
                yield app


@pytest.fixture
def client(app) -> Generator:
    """Create test client."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
async def async_client(app) -> AsyncIterator:
    """Create async test client."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def test_user() -> dict:
    """Create test user data."""
    return {
        "user_id": "test-user-id",
        "email": "test@example.com",
        "name": "Test User",
        "roles": ["user"],
    }


@pytest.fixture
def auth_headers(test_user: dict) -> dict:
    """Create authorization headers with valid JWT."""
    from datetime import datetime, timedelta, timezone
    from jose import jwt
    from core.config import get_settings
    
    settings = get_settings()
    
    payload = {
        "sub": test_user["user_id"],
        "email": test_user["email"],
        "roles": test_user["roles"],
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc),
    }
    
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def test_project() -> dict:
    """Create test project data."""
    return {
        "project_id": "test-project-id",
        "name": "Test Project",
        "description": "Test project description",
        "status": "active",
        "scope": ["example.com", "*.example.com"],
        "out_of_scope": [],
        "tags": ["test"],
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": None,
        "owner_id": "test-user-id",
    }


@pytest.fixture
def test_scan() -> dict:
    """Create test scan data."""
    return {
        "scan_id": "test-scan-id",
        "project_id": "test-project-id",
        "target": "example.com",
        "scan_type": "full_recon",
        "status": "completed",
        "progress": 100.0,
        "phase": "finalization",
        "started_at": "2024-01-01T00:00:00Z",
        "completed_at": "2024-01-01T01:00:00Z",
        "duration_seconds": 3600,
        "findings_count": 10,
        "error_message": None,
        "created_at": "2024-01-01T00:00:00Z",
    }


@pytest.fixture
def test_vulnerability() -> dict:
    """Create test vulnerability data."""
    return {
        "vulnerability_id": "test-vuln-id",
        "template_id": "CVE-2021-44228",
        "name": "Log4j Remote Code Execution",
        "description": "Apache Log4j2 RCE vulnerability",
        "severity": "critical",
        "cvss_score": 10.0,
        "cve_id": "CVE-2021-44228",
        "cwe_id": "CWE-502",
        "matched_at": "https://example.com/api",
        "evidence": "Vulnerable JNDI lookup detected",
        "remediation": "Update Log4j to version 2.17.0 or later",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        "created_at": "2024-01-01T00:00:00Z",
        "project_id": "test-project-id",
    }
