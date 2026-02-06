"""
Kiterunner API discovery orchestrator.

Runs Kiterunner on seed URLs to discover API endpoints.
Pipeline stores endpoints via _store_kiterunner_endpoints.
"""

from __future__ import annotations

from typing import Any

from core.config import get_settings
from core.logging import get_logger
from recon.orchestrators.types import PhaseResult
from recon.tools.kiterunner import KiterunnerTool


logger = get_logger(__name__)


async def run_kiterunner(
    seed_urls: list[str],
    options: dict | None = None,
) -> PhaseResult:
    """
    Run Kiterunner on each seed URL. Returns endpoints_by_url: list of { base_url, endpoints }.
    Pipeline calls _store_kiterunner_endpoints(base_url, endpoints) for each.
    """
    opts = options or {}
    max_urls = opts.get("max_urls", 3)
    urls = [u.strip() for u in seed_urls if u and u.strip()][:max_urls]
    if not urls or not (get_settings().MCP_KITERUNNER_URL or "").strip():
        return PhaseResult(success=True, data={"endpoints_by_url": []})

    tool = KiterunnerTool()
    endpoints_by_url: list[dict[str, Any]] = []
    total_endpoints = 0
    try:
        for url in urls:
            try:
                result = await tool.run(url)
                if result.success and result.data and result.data.get("endpoints"):
                    endpoints = result.data["endpoints"]
                    endpoints_by_url.append({"base_url": url, "endpoints": endpoints})
                    total_endpoints += min(len(endpoints), 500)
            except Exception as e:
                logger.debug("Kiterunner failed for URL", url=url, error=str(e))
        await tool.close()
    except Exception as e:
        logger.warning("Kiterunner orchestrator failed", error=str(e))
        return PhaseResult(success=False, data={}, error=str(e))
    return PhaseResult(
        success=True,
        data={"endpoints_by_url": endpoints_by_url},
        findings_delta=total_endpoints,
    )
