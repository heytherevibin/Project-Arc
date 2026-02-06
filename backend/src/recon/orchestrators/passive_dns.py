"""
Passive DNS / Certificate Transparency orchestrator.

Uses CT logs (crt.sh) to discover subdomains for a domain.
Pipeline stores results in Neo4j.
"""

from __future__ import annotations

import httpx

from core.logging import get_logger
from recon.orchestrators.types import PhaseResult
from recon.passive.cert_transparency import CertTransparency


logger = get_logger(__name__)


async def run_passive_dns(
    target: str,
    options: dict | None = None,
) -> PhaseResult:
    """
    Run passive DNS / CT log discovery for the target domain.
    Returns subdomains list in data["subdomains"].
    """
    opts = options or {}
    domain = (target or "").strip()
    if not domain:
        return PhaseResult(success=False, error="target domain is required")

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            ct = CertTransparency(http_client=client)
            result = await ct.search(
                domain,
                include_expired=opts.get("include_expired", False),
                deduplicate=True,
            )
        subdomains = list(result.subdomains) if result.subdomains else []
        logger.info("Passive DNS complete", domain=domain, subdomains=len(subdomains))
        return PhaseResult(
            success=True,
            data={"subdomains": subdomains, "total_certs": result.total_certs},
            findings_delta=len(subdomains),
        )
    except Exception as e:
        logger.warning("Passive DNS failed", domain=domain, error=str(e))
        return PhaseResult(success=False, data={}, error=str(e), findings_delta=0)
