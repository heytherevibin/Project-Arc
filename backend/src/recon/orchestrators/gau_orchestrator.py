"""
GAU (Get All URLs) orchestrator.

Discovers URLs for a domain from wayback, etc. Pipeline stores via _store_urls_from_gau.
"""

from __future__ import annotations

from core.config import get_settings
from core.logging import get_logger
from recon.orchestrators.types import PhaseResult
from recon.tools.gau import GauTool


logger = get_logger(__name__)


async def run_gau(
    target: str,
    options: dict | None = None,
) -> PhaseResult:
    """
    Run GAU for the target domain. Returns urls list.
    Pipeline calls _store_urls_from_gau(urls).
    """
    domain = (target or "").strip()
    if not domain or not (get_settings().MCP_GAU_URL or "").strip():
        return PhaseResult(success=True, data={"urls": []})

    tool = GauTool()
    try:
        result = await tool.run(domain)
        await tool.close()
        if not result.success:
            return PhaseResult(success=False, data={}, error=result.error or "GAU failed")
        urls = result.data.get("urls", []) if result.data else []
        return PhaseResult(
            success=True,
            data={"urls": urls},
            findings_delta=min(len(urls), 2000),
        )
    except Exception as e:
        logger.warning("GAU orchestrator failed", target=domain, error=str(e))
        return PhaseResult(success=False, data={}, error=str(e))
