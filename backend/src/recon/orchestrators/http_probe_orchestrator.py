"""
HTTP probe orchestrator.

Runs Httpx against URL candidates (built from subdomains and optional ports).
Pipeline stores probed URLs in Neo4j.
"""

from __future__ import annotations

from core.logging import get_logger
from recon.orchestrators.types import PhaseResult
from recon.tools.httpx import HttpxTool


logger = get_logger(__name__)


def _build_url_candidates(
    subdomains: list[str],
    open_ports: dict[str, list[int]],
    resolved_ips: dict[str, list[str]],
    target_fallback: str,
) -> list[str]:
    """Build URL list for probing: https/http per subdomain plus non-80/443 ports."""
    urls: list[str] = []
    seen: set[str] = set()
    for subdomain in subdomains:
        for scheme in ("https", "http"):
            u = f"{scheme}://{subdomain}"
            if u not in seen:
                seen.add(u)
                urls.append(u)
        for ip in resolved_ips.get(subdomain, []):
            for port in open_ports.get(ip, []):
                if port not in (80, 443):
                    for scheme in ("https", "http"):
                        u = f"{scheme}://{subdomain}:{port}"
                        if u not in seen:
                            seen.add(u)
                            urls.append(u)
    if not urls and target_fallback:
        urls = [f"https://{target_fallback}", f"http://{target_fallback}"]
    return urls


async def run_http_probe(
    subdomains: list[str],
    open_ports: dict[str, list[int]],
    resolved_ips: dict[str, list[str]],
    target_fallback: str,
    options: dict | None = None,
) -> PhaseResult:
    """
    Run HTTP probing (Httpx). Returns live_urls and probed (list of dicts per URL).
    Pipeline stores via _store_urls(probed).
    """
    urls_to_probe = _build_url_candidates(
        subdomains, open_ports, resolved_ips, target_fallback or ""
    )
    if not urls_to_probe:
        return PhaseResult(success=True, data={"live_urls": [], "probed": []})

    tool = HttpxTool()
    result = await tool.run(urls_to_probe)
    await tool.close()
    if not result.success:
        logger.warning("HTTP probe failed", error=result.error)
        return PhaseResult(success=False, data={}, error=result.error or "Httpx failed")
    live_urls = result.data.get("live_urls", []) if result.data else []
    probed = result.data.get("probed", []) if result.data else []
    logger.info("HTTP probe complete", probed=len(urls_to_probe), live=len(live_urls))
    return PhaseResult(
        success=True,
        data={"live_urls": live_urls, "probed": probed},
        findings_delta=len(probed),
    )
