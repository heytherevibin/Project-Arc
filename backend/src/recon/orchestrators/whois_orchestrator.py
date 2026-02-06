"""
Whois enrichment orchestrator.

Runs Whois lookup for a domain. Pipeline stores via _store_whois.
"""

from __future__ import annotations

from core.config import get_settings
from core.logging import get_logger
from recon.orchestrators.types import PhaseResult
from recon.tools.whois import WhoisTool


logger = get_logger(__name__)


async def run_whois(
    target: str,
    options: dict | None = None,
) -> PhaseResult:
    """
    Run Whois for the target domain. Returns whois (dict), raw (str).
    Pipeline calls _store_whois(domain, whois_dict, raw).
    """
    domain = (target or "").strip()
    if not domain or not (get_settings().MCP_WHOIS_URL or "").strip():
        return PhaseResult(success=True, data={"whois": {}, "raw": None})

    tool = WhoisTool()
    try:
        result = await tool.run(domain)
        await tool.close()
        if not result.success:
            return PhaseResult(success=False, data={}, error=result.error or "Whois failed")
        whois = result.data.get("whois", {}) if result.data else {}
        raw = result.data.get("raw") if result.data else None
        return PhaseResult(success=True, data={"whois": whois, "raw": raw}, findings_delta=1 if whois else 0)
    except Exception as e:
        logger.warning("Whois orchestrator failed", target=domain, error=str(e))
        return PhaseResult(success=False, data={}, error=str(e))
