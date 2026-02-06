"""
Knockpy subdomain brute-force orchestrator.

Standalone orchestrator for Knockpy when run outside subdomain enumeration.
Pipeline stores via _store_subdomains(..., discovery_source="knockpy").
"""

from __future__ import annotations

from core.config import get_settings
from core.logging import get_logger
from recon.orchestrators.types import PhaseResult
from recon.tools.knockpy import KnockpyTool


logger = get_logger(__name__)


async def run_knockpy(
    target: str,
    options: dict | None = None,
) -> PhaseResult:
    """
    Run Knockpy against a domain. Returns subdomains list.
    Pipeline calls _store_subdomains(subdomains, discovery_source="knockpy").
    """
    domain = (target or "").strip()
    if not domain or not (get_settings().MCP_KNOCKPY_URL or "").strip():
        return PhaseResult(success=True, data={"subdomains": []})

    tool = KnockpyTool()
    try:
        result = await tool.run(domain)
        await tool.close()
        if not result.success:
            return PhaseResult(success=False, data={}, error=result.error or "Knockpy failed")
        subs = result.data.get("subdomains", []) if result.data else []
        subdomains = [str(s).strip() for s in subs if s]
        return PhaseResult(
            success=True,
            data={"subdomains": subdomains},
            findings_delta=len(subdomains),
        )
    except Exception as e:
        logger.warning("Knockpy orchestrator failed", target=domain, error=str(e))
        return PhaseResult(success=False, data={}, error=str(e))
