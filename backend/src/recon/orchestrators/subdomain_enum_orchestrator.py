"""
Subdomain enumeration orchestrator.

Runs Subfinder, optionally Knockpy when enabled, then DNS resolution via dnsx.
Pipeline stores subdomains and resolution in Neo4j.
"""

from __future__ import annotations

from core.config import get_settings
from core.logging import get_logger
from recon.orchestrators.types import PhaseResult
from recon.tools.dnsx import DnsxTool
from recon.tools.knockpy import KnockpyTool
from recon.tools.subfinder import SubfinderTool


logger = get_logger(__name__)


async def run_subdomain_enumeration(
    target: str,
    options: dict | None = None,
) -> PhaseResult:
    """
    Run subdomain enumeration (Subfinder, optionally Knockpy) then DNS resolution (dnsx).
    Set options["knockpy_enabled"] = True to run Knockpy (requires MCP_KNOCKPY_URL).
    Returns subdomains list and resolved: { subdomain: [ips] }.
    """
    domain = (target or "").strip()
    if not domain:
        return PhaseResult(success=False, error="target domain is required")
    opts = options or {}
    knockpy_enabled = opts.get("knockpy_enabled", False) and bool(
        (get_settings().MCP_KNOCKPY_URL or "").strip()
    )

    subdomains: list[str] = []
    seen: set[str] = set()

    # Subfinder
    subfinder = SubfinderTool()
    result = await subfinder.run(domain)
    if result.success and result.data:
        subdomains = result.data.get("subdomains", [])
        seen = set(subdomains)
        logger.info("Subfinder complete", target=domain, count=len(subdomains))
    else:
        logger.warning("Subfinder failed", target=domain, error=result.error)
    await subfinder.close()

    # Optional Knockpy
    if knockpy_enabled:
        knockpy = KnockpyTool()
        try:
            kr = await knockpy.run(domain)
            await knockpy.close()
            if kr.success and kr.data and kr.data.get("subdomains"):
                extra = [str(s).strip() for s in kr.data["subdomains"] if s and str(s).strip() not in seen]
                for s in extra:
                    seen.add(s)
                subdomains = list(seen)
                logger.info("Knockpy complete", target=domain, extra=len(extra))
        except Exception as e:
            logger.debug("Knockpy optional run failed", error=str(e))
            await knockpy.close()

    if not subdomains:
        subdomains = [domain]

    # DNS resolution
    dnsx = DnsxTool()
    dns_result = await dnsx.run(subdomains)
    await dnsx.close()
    resolved: dict[str, list[str]] = {}
    if dns_result.success and dns_result.data:
        resolved = dns_result.data.get("resolved", {})
        logger.info("DNS resolution complete", resolved_count=len(resolved))
    else:
        logger.warning("dnsx failed", error=dns_result.error)

    return PhaseResult(
        success=True,
        data={"subdomains": subdomains, "resolved": resolved},
        findings_delta=len(subdomains),
        error=dns_result.error if not dns_result.success else None,
    )
