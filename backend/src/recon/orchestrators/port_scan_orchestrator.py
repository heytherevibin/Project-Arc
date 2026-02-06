"""
Port scan orchestrator.

Runs Naabu against a list of IPs (or single target).
Pipeline stores ports in Neo4j.
"""

from __future__ import annotations

from core.logging import get_logger
from recon.orchestrators.types import PhaseResult
from recon.tools.naabu import NaabuTool


logger = get_logger(__name__)


async def run_port_scan(
    ips: list[str],
    target_fallback: str | None = None,
    options: dict | None = None,
) -> PhaseResult:
    """
    Run port scan (Naabu) on given IPs. Returns ports: { ip: [port, ...] }.
    If ips is empty, uses target_fallback as single host.
    """
    opts = options or {}
    hosts = list(ips) if ips else []
    if not hosts and target_fallback:
        hosts = [target_fallback]
    if not hosts:
        return PhaseResult(success=True, data={"ports": {}})

    tool = NaabuTool()
    result = await tool.run(hosts)
    await tool.close()
    if not result.success:
        logger.warning("Port scan failed", error=result.error)
        return PhaseResult(success=False, data={}, error=result.error or "Naabu failed")
    ports = result.data.get("ports", {}) if result.data else {}
    total = sum(len(p) for p in ports.values())
    logger.info("Port scan complete", hosts=len(hosts), total_ports=total)
    return PhaseResult(success=True, data={"ports": ports}, findings_delta=total)
