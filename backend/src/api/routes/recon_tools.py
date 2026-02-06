"""
Extended recon tool endpoints.

Run extended recon tools (GAU, Whois, Shodan, etc.) via MCP in real time. No mocks; all calls hit MCP servers.
"""

from typing import Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from api.dependencies import get_current_user
from recon.tools.gau import GauTool
from recon.tools.github_recon import GitHubReconTool
from recon.tools.kiterunner import KiterunnerTool
from recon.tools.knockpy import KnockpyTool
from recon.tools.shodan import ShodanTool
from recon.tools.wappalyzer import WappalyzerTool
from recon.tools.whois import WhoisTool


router = APIRouter()


class GauRequest(BaseModel):
    """Request for GAU URL discovery."""
    domain: str = Field(..., min_length=1, description="Domain to fetch URLs for")


class WhoisRequest(BaseModel):
    """Request for WHOIS lookup."""
    domain: str = Field(..., min_length=1, description="Domain to look up")


class ShodanRequest(BaseModel):
    """Request for Shodan lookup (IP or domain)."""
    target: str = Field(..., min_length=1, description="IP address or domain")


class WappalyzerRequest(BaseModel):
    """Request for Wappalyzer tech fingerprinting."""
    url: str = Field(..., min_length=1, description="URL to analyze")


class KiterunnerRequest(BaseModel):
    """Request for Kiterunner API discovery."""
    url: str = Field(..., min_length=1, description="Base URL to scan")


class KnockpyRequest(BaseModel):
    """Request for Knockpy subdomain brute-force."""
    domain: str = Field(..., min_length=1, description="Target domain")


class GitHubSearchRequest(BaseModel):
    """Request for GitHub search."""
    query: str = Field(..., min_length=1, description="Search query (e.g. org:company)")


def _result_to_response(result: Any) -> dict[str, Any]:
    """Convert ToolResult to API response. MCP returns structured JSON (success + tool-specific keys)."""
    if result.data and isinstance(result.data, dict):
        return dict(result.data)
    return {"success": result.success, "error": result.error, "data": result.data}


@router.post("/gau", status_code=status.HTTP_200_OK)
async def run_gau(req: GauRequest, _: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Run GAU URL discovery for a domain. Real MCP call."""
    tool = GauTool()
    result = await tool.run(req.domain)
    await tool.close()
    return _result_to_response(result)


@router.post("/whois", status_code=status.HTTP_200_OK)
async def run_whois(req: WhoisRequest, _: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Run WHOIS lookup for a domain. Real MCP call."""
    tool = WhoisTool()
    result = await tool.run(req.domain)
    await tool.close()
    return _result_to_response(result)


@router.post("/shodan", status_code=status.HTTP_200_OK)
async def run_shodan(req: ShodanRequest, _: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Run Shodan lookup for an IP or domain. Real MCP call."""
    tool = ShodanTool()
    result = await tool.run(req.target)
    await tool.close()
    return _result_to_response(result)


@router.post("/wappalyzer", status_code=status.HTTP_200_OK)
async def run_wappalyzer(req: WappalyzerRequest, _: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Run Wappalyzer tech fingerprinting for a URL. Real MCP call."""
    tool = WappalyzerTool()
    result = await tool.run(req.url)
    await tool.close()
    return _result_to_response(result)


@router.post("/kiterunner", status_code=status.HTTP_200_OK)
async def run_kiterunner(req: KiterunnerRequest, _: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Run Kiterunner API discovery for a base URL. Real MCP call."""
    tool = KiterunnerTool()
    result = await tool.run(req.url)
    await tool.close()
    return _result_to_response(result)


@router.post("/knockpy", status_code=status.HTTP_200_OK)
async def run_knockpy(req: KnockpyRequest, _: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Run Knockpy subdomain brute-force for a domain. Real MCP call."""
    tool = KnockpyTool()
    result = await tool.run(req.domain)
    await tool.close()
    return _result_to_response(result)


@router.post("/github_search", status_code=status.HTTP_200_OK)
async def run_github_search(req: GitHubSearchRequest, _: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Run GitHub repo/code search. Real MCP call (uses GITHUB_TOKEN on MCP)."""
    tool = GitHubReconTool()
    result = await tool.run(req.query)
    await tool.close()
    return _result_to_response(result)
