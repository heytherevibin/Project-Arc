"""
Wappalyzer technology fingerprint orchestrator.

Runs Wappalyzer on URLs to detect technologies. Pipeline stores via _store_technologies.
"""

from __future__ import annotations

from typing import Any

from core.config import get_settings
from core.logging import get_logger
from recon.orchestrators.types import PhaseResult
from recon.tools.wappalyzer import WappalyzerTool


logger = get_logger(__name__)


async def run_wappalyzer(
    urls: list[str],
    options: dict | None = None,
) -> PhaseResult:
    """
    Run Wappalyzer on each URL. Returns url_technologies: [ { url, technologies }, ... ].
    Pipeline calls _store_technologies(url_technologies).
    """
    opts = options or {}
    max_urls = opts.get("max_urls", 5)
    url_list = [u.strip() for u in urls if u and u.strip()][:max_urls]
    if not url_list or not (get_settings().MCP_WAPPALYZER_URL or "").strip():
        return PhaseResult(success=True, data={"url_technologies": []})

    tool = WappalyzerTool()
    url_techs: list[dict[str, Any]] = []
    try:
        for url in url_list:
            try:
                res = await tool.run(url)
                if res.success and res.data and res.data.get("technologies"):
                    url_techs.append({"url": url, "technologies": res.data["technologies"]})
            except Exception:
                pass
        await tool.close()
    except Exception as e:
        logger.warning("Wappalyzer orchestrator failed", error=str(e))
        return PhaseResult(success=False, data={}, error=str(e))
    return PhaseResult(
        success=True,
        data={"url_technologies": url_techs},
        findings_delta=len(url_techs),
    )
