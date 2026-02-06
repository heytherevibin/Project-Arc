"""
CALDERA Client

Integration with MITRE CALDERA for automated adversary emulation.
CALDERA provides pre-built adversary profiles (APT groups) and
atomic test execution for red team validation.

This client wraps the CALDERA REST API to:
  - List available adversary profiles
  - Create and manage operations
  - Retrieve operation results
  - Map CALDERA abilities to Arc's tool framework
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from core.config import get_settings
from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class AdversaryProfile:
    """A CALDERA adversary profile."""
    adversary_id: str
    name: str
    description: str
    atomic_ordering: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class CalderaOperation:
    """A CALDERA operation (running adversary emulation)."""
    operation_id: str
    name: str
    adversary_id: str
    state: str                # "running", "finished", "paused", "cleanup"
    start_time: str = ""
    end_time: str = ""
    steps_completed: int = 0
    steps_total: int = 0


class CalderaClient:
    """
    CALDERA REST API client.

    Requires a running CALDERA server with the REST API enabled.
    Configure via CALDERA_URL and CALDERA_API_KEY in environment.
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
    ) -> None:
        settings = get_settings()
        self._base_url = base_url or getattr(settings, "CALDERA_URL", "http://localhost:8888")
        self._api_key = api_key or getattr(settings, "CALDERA_API_KEY", "ADMIN123")
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self._base_url.rstrip("/"),
                headers={"KEY": self._api_key},
                timeout=30.0,
            )
        return self._client

    async def health_check(self) -> bool:
        """Check if CALDERA server is reachable."""
        try:
            client = await self._get_client()
            resp = await client.get("/api/v2/health")
            return resp.status_code == 200
        except Exception:
            return False

    async def list_adversaries(self) -> list[AdversaryProfile]:
        """List available adversary profiles."""
        try:
            client = await self._get_client()
            resp = await client.get("/api/v2/adversaries")
            resp.raise_for_status()
            data = resp.json()

            return [
                AdversaryProfile(
                    adversary_id=a.get("adversary_id", ""),
                    name=a.get("name", ""),
                    description=a.get("description", ""),
                    atomic_ordering=a.get("atomic_ordering", []),
                    tags=a.get("tags", []),
                )
                for a in data
            ]
        except Exception as e:
            logger.warning("Failed to list CALDERA adversaries", error=str(e))
            return []

    async def create_operation(
        self,
        name: str,
        adversary_id: str,
        group: str = "red",
        auto_close: bool = True,
    ) -> CalderaOperation | None:
        """Create and start a CALDERA operation."""
        try:
            client = await self._get_client()
            resp = await client.post(
                "/api/v2/operations",
                json={
                    "name": name,
                    "adversary": {"adversary_id": adversary_id},
                    "group": group,
                    "auto_close": auto_close,
                },
            )
            resp.raise_for_status()
            data = resp.json()

            op = CalderaOperation(
                operation_id=data.get("id", ""),
                name=data.get("name", name),
                adversary_id=adversary_id,
                state=data.get("state", "running"),
                start_time=data.get("start", ""),
            )

            logger.info(
                "CALDERA operation created",
                operation_id=op.operation_id,
                adversary=adversary_id,
            )
            return op

        except Exception as e:
            logger.error("Failed to create CALDERA operation", error=str(e))
            return None

    async def get_operation(self, operation_id: str) -> CalderaOperation | None:
        """Get the status of a CALDERA operation."""
        try:
            client = await self._get_client()
            resp = await client.get(f"/api/v2/operations/{operation_id}")
            resp.raise_for_status()
            data = resp.json()

            chain = data.get("chain", [])
            completed = sum(1 for link in chain if link.get("status") == 0)

            return CalderaOperation(
                operation_id=data.get("id", operation_id),
                name=data.get("name", ""),
                adversary_id=data.get("adversary", {}).get("adversary_id", ""),
                state=data.get("state", "unknown"),
                start_time=data.get("start", ""),
                steps_completed=completed,
                steps_total=len(chain),
            )
        except Exception as e:
            logger.warning("Failed to get CALDERA operation", error=str(e))
            return None

    async def get_operation_results(self, operation_id: str) -> list[dict[str, Any]]:
        """Get detailed results from a CALDERA operation."""
        try:
            client = await self._get_client()
            resp = await client.get(f"/api/v2/operations/{operation_id}/links")
            resp.raise_for_status()

            results = []
            for link in resp.json():
                results.append({
                    "ability_id": link.get("ability", {}).get("ability_id", ""),
                    "ability_name": link.get("ability", {}).get("name", ""),
                    "technique_id": link.get("ability", {}).get("technique_id", ""),
                    "status": link.get("status"),
                    "output": link.get("output", ""),
                    "host": link.get("host", ""),
                    "pid": link.get("pid"),
                })
            return results
        except Exception as e:
            logger.warning("Failed to get CALDERA results", error=str(e))
            return []

    async def stop_operation(self, operation_id: str) -> bool:
        """Stop a running CALDERA operation."""
        try:
            client = await self._get_client()
            resp = await client.patch(
                f"/api/v2/operations/{operation_id}",
                json={"state": "stop"},
            )
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
