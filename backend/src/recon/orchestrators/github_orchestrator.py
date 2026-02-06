"""
GitHub recon orchestrator.

Searches GitHub for org/repos and code findings by target domain.
Pipeline stores repos and findings in Neo4j.
"""

from __future__ import annotations

from core.logging import get_logger
from recon.orchestrators.types import PhaseResult
from recon.tools.github_recon import GitHubReconTool


logger = get_logger(__name__)


async def run_github_recon(
    target: str,
    query_template: str | None = None,
    options: dict | None = None,
) -> PhaseResult:
    """
    Run GitHub recon (org search + code search). Returns repos and findings.
    Pipeline calls _store_github_repos and _store_github_findings.
    """
    domain = (target or "").strip()
    if not domain:
        return PhaseResult(success=False, error="target domain is required")
    query = query_template or f"org:{domain}"

    tool = GitHubReconTool()
    try:
        result = await tool.run(query)
        await tool.close()
        if not result.success:
            return PhaseResult(success=False, data={}, error=result.error or "GitHub recon failed")
        repos = result.data.get("repos", [])
        findings = result.data.get("findings", [])
        delta = min(len(repos), 200) + min(len(findings), 200)
        logger.info("GitHub recon complete", target=domain, repos=len(repos), findings=len(findings))
        return PhaseResult(
            success=True,
            data={"repos": repos, "findings": findings},
            findings_delta=delta,
        )
    except Exception as e:
        logger.warning("GitHub recon failed", target=domain, error=str(e))
        return PhaseResult(success=False, data={}, error=str(e), findings_delta=0)
