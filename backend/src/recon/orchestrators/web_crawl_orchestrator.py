"""
Web crawl orchestrator.

Runs Katana on a list of seed URLs to discover endpoints.
Pipeline stores discovered URLs/endpoints in Neo4j.
"""

from __future__ import annotations

from core.logging import get_logger
from recon.orchestrators.types import PhaseResult
from recon.tools.katana import KatanaTool


logger = get_logger(__name__)


async def run_web_crawl(
    seed_urls: list[str],
    options: dict | None = None,
) -> PhaseResult:
    """
    Run web crawl (Katana) on seed URLs. Returns discovered_urls list.
    Pipeline stores via _store_endpoints(discovered_urls).
    """
    opts = options or {}
    max_seeds = opts.get("max_seed_urls", 50)
    urls = list(seed_urls)[:max_seeds] if seed_urls else []
    if not urls:
        logger.info("No seed URLs for web crawl")
        return PhaseResult(success=True, data={"discovered_urls": []})

    tool = KatanaTool()
    result = await tool.run(urls)
    await tool.close()
    if not result.success:
        logger.warning("Web crawl failed", error=result.error)
        return PhaseResult(success=False, data={}, error=result.error or "Katana failed")
    discovered = result.data.get("discovered_urls", []) if result.data else []
    logger.info("Web crawl complete", seeds=len(urls), discovered=len(discovered))
    return PhaseResult(
        success=True,
        data={"discovered_urls": discovered},
        findings_delta=min(len(discovered), 2000),
    )
