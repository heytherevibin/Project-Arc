"""
GitHub Recon MCP Server

Repo and code search via GitHub API. Uses GITHUB_TOKEN from env; real API calls only.
"""

import os
from typing import Any

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="GitHub Recon MCP Server",
    description="GitHub repo and code search via GitHub API",
    version="1.0.0",
)

GITHUB_API = "https://api.github.com"


class GitHubReconRequest(BaseModel):
    """Request model for GitHub recon."""
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    query: str = Field(..., description="Search query (e.g. org:company, repo:user/repo, keyword)")
    search_type: str = Field("repositories", description="repositories or code")
    per_page: int = Field(30, ge=1, le=100, description="Results per page")


class GitHubReconResponse(BaseModel):
    """Response model for GitHub recon."""
    success: bool
    repos: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    total_count: int = 0
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint to verify this is the GitHub Recon MCP server."""
    return {"tool": "github_recon", "path": "/tools/github_search", "status": "ok"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    token = (os.environ.get("GITHUB_TOKEN") or "").strip()
    return {"status": "healthy", "tool": "github_recon", "token_set": "yes" if token else "no"}


@app.post("/tools/github_search", response_model=GitHubReconResponse)
async def github_search(request: GitHubReconRequest) -> GitHubReconResponse:
    """
    Search GitHub repositories or code using the GitHub API.
    Requires GITHUB_TOKEN in environment for higher rate limits and private access.
    """
    token = (os.environ.get("GITHUB_TOKEN") or "").strip()
    if not token:
        return GitHubReconResponse(
            success=False,
            error="GITHUB_TOKEN not set. Set GITHUB_TOKEN in .env for GitHub API search (required for recon).",
        )

    query = (request.query or "").strip()
    if not query:
        return GitHubReconResponse(success=False, error="query is required")

    search_type = (request.search_type or "repositories").strip().lower()
    if search_type not in ("repositories", "code"):
        search_type = "repositories"
    per_page = max(1, min(100, request.per_page))

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {token}",
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            if search_type == "repositories":
                r = await client.get(
                    f"{GITHUB_API}/search/repositories",
                    params={"q": query, "per_page": per_page, "sort": "updated"},
                    headers=headers,
                )
            else:
                r = await client.get(
                    f"{GITHUB_API}/search/code",
                    params={"q": query, "per_page": per_page},
                    headers=headers,
                )

        if r.status_code == 403:
            return GitHubReconResponse(success=False, error="GitHub API rate limited or token invalid")
        if r.status_code != 200:
            return GitHubReconResponse(success=False, error=f"GitHub API {r.status_code}: {r.text[:400]}")

        data = r.json()
        total_count = data.get("total_count", 0)
        items = data.get("items", [])

        if search_type == "repositories":
            repos = [
                {
                    "full_name": x.get("full_name"),
                    "html_url": x.get("html_url"),
                    "description": x.get("description"),
                    "updated_at": x.get("updated_at"),
                }
                for x in items
            ]
            return GitHubReconResponse(success=True, repos=repos, total_count=total_count)
        # code search
        findings = [
            {
                "path": x.get("path"),
                "repository": x.get("repository", {}).get("full_name"),
                "html_url": x.get("html_url"),
            }
            for x in items
        ]
        return GitHubReconResponse(success=True, findings=findings, total_count=total_count)
    except httpx.HTTPError as e:
        return GitHubReconResponse(success=False, error=str(e))


@app.get("/tools/github_search/schema")
async def get_schema() -> dict[str, Any]:
    """Return the tool schema for MCP."""
    return {
        "name": "github_search",
        "description": "Search GitHub repositories or code (requires GITHUB_TOKEN)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query (e.g. org:company)"},
                "search_type": {"type": "string", "enum": ["repositories", "code"], "default": "repositories"},
                "per_page": {"type": "integer", "default": 30},
            },
            "required": ["query"],
        },
    }
}
