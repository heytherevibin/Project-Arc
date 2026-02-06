"""
Certificate Transparency

Queries crt.sh for certificate transparency logs to discover
subdomains associated with a target domain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class CTResult:
    """Certificate Transparency search result."""
    domain: str
    subdomains: list[str] = field(default_factory=list)
    certificates: list[dict[str, Any]] = field(default_factory=list)
    total_certs: int = 0


class CertTransparency:
    """
    Queries certificate transparency logs (crt.sh) for subdomain discovery.

    Can also integrate with Censys API if credentials are provided.
    """

    CRT_SH_URL = "https://crt.sh"

    def __init__(self, http_client: Any | None = None) -> None:
        """
        Parameters
        ----------
        http_client : optional httpx.AsyncClient or similar
        """
        self._http = http_client

    async def search(
        self,
        domain: str,
        include_expired: bool = False,
        deduplicate: bool = True,
    ) -> CTResult:
        """
        Query crt.sh for certificates matching the domain.

        Returns discovered subdomains from CT log entries.
        """
        result = CTResult(domain=domain)

        try:
            certs = await self._query_crtsh(domain, include_expired)
            result.certificates = certs
            result.total_certs = len(certs)

            # Extract subdomains
            subdomains: set[str] = set()
            for cert in certs:
                name_value = cert.get("name_value", "")
                for line in name_value.split("\n"):
                    clean = line.strip().lower()
                    if clean and not clean.startswith("*") and domain in clean:
                        subdomains.add(clean)

            result.subdomains = sorted(subdomains)

            logger.info(
                "CT search complete",
                domain=domain,
                certs=len(certs),
                subdomains=len(result.subdomains),
            )

        except Exception as exc:
            logger.warning("CT search failed", domain=domain, error=str(exc))

        return result

    async def _query_crtsh(
        self,
        domain: str,
        include_expired: bool,
    ) -> list[dict[str, Any]]:
        """Query crt.sh JSON API."""
        if self._http is None:
            # If no HTTP client, return empty (tool will be wired at runtime)
            logger.debug("No HTTP client configured for CT queries")
            return []

        params: dict[str, Any] = {
            "q": f"%.{domain}",
            "output": "json",
        }
        if not include_expired:
            params["exclude"] = "expired"

        url = f"{self.CRT_SH_URL}/"

        try:
            response = await self._http.get(url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return data if isinstance(data, list) else []
        except Exception as exc:
            logger.warning("crt.sh query failed", error=str(exc))

        return []
