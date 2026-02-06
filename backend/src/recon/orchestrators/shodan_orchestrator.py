"""
Shodan enrichment orchestrator.

Looks up IPs (and optionally domain) via Shodan/InternetDB.
Pipeline stores results in Neo4j (ShodanData nodes).
"""

from __future__ import annotations

from core.logging import get_logger
from recon.orchestrators.types import PhaseResult
from recon.tools.shodan import ShodanTool


logger = get_logger(__name__)


async def run_shodan_enrichment(
    ips: list[str],
    options: dict | None = None,
) -> PhaseResult:
    """
    Run Shodan lookup for each IP. Returns ip_data: { ip: { ... } }.
    Pipeline calls _store_shodan_data(ip_data).
    """
    opts = options or {}
    limit = opts.get("max_ips", 15)
    ips_to_query = list(ips)[:limit] if ips else []
    if not ips_to_query:
        return PhaseResult(success=True, data={"ip_data": {}})

    tool = ShodanTool()
    ip_data: dict[str, dict] = {}
    try:
        for ip in ips_to_query:
            try:
                result = await tool.run(ip)
                if result.success and result.data:
                    raw = result.data.get("data")
                    ip_data[ip] = raw if isinstance(raw, dict) else {"raw": raw}
            except Exception as e:
                logger.debug("Shodan lookup failed for IP", ip=ip, error=str(e))
        await tool.close()
    except Exception as e:
        logger.warning("Shodan enrichment failed", error=str(e))
        return PhaseResult(success=False, data={}, error=str(e))
    return PhaseResult(success=True, data={"ip_data": ip_data}, findings_delta=len(ip_data))
