"""
Settings API.

Pipeline extended tools and other app-level settings (stored in Neo4j, overridable via UI).
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from api.dependencies import get_current_user
from graph.client import get_neo4j_client
from graph.settings_store import (
    PIPELINE_EXTENDED_TOOLS_ALLOWED,
    get_pipeline_extended_tools,
    set_pipeline_extended_tools,
)


router = APIRouter()


# =============================================================================
# Request/Response Models
# =============================================================================

class PipelineToolsResponse(BaseModel):
    """Pipeline extended tools list."""
    tools: list[str] = Field(..., description="Tool ids enabled in pipeline (whois, gau, wappalyzer, shodan, knockpy, kiterunner, github_recon)")


class PipelineToolsUpdate(BaseModel):
    """Update pipeline extended tools."""
    tools: list[str] = Field(..., description="Tool ids to enable (subset of allowed)")


# =============================================================================
# Endpoints
# =============================================================================

@router.get(
    "/pipeline-tools",
    response_model=PipelineToolsResponse,
    summary="Get pipeline extended tools",
    description="Return which extended recon tools run in the pipeline (from Settings or config default).",
)
async def get_pipeline_tools(
    _: dict = Depends(get_current_user),
) -> PipelineToolsResponse:
    """Get enabled pipeline extended tools."""
    client = get_neo4j_client()
    tools = await get_pipeline_extended_tools(client)
    return PipelineToolsResponse(tools=tools)


@router.put(
    "/pipeline-tools",
    response_model=PipelineToolsResponse,
    summary="Update pipeline extended tools",
    description="Set which extended recon tools run in the pipeline. Only allowed ids are applied.",
)
async def update_pipeline_tools(
    data: PipelineToolsUpdate,
    _: dict = Depends(get_current_user),
) -> PipelineToolsResponse:
    """Update enabled pipeline extended tools."""
    client = get_neo4j_client()
    await set_pipeline_extended_tools(client, data.tools)
    tools = await get_pipeline_extended_tools(client)
    return PipelineToolsResponse(tools=tools)


@router.get(
    "/pipeline-tools/options",
    response_model=dict,
    summary="Pipeline tool options",
    description="Return allowed tool ids and labels for the Settings UI.",
)
async def get_pipeline_tool_options(
    _: dict = Depends(get_current_user),
) -> dict:
    """Return allowed tool ids and display labels."""
    options = [
        {"id": "whois", "label": "Whois"},
        {"id": "gau", "label": "GAU (URL discovery)"},
        {"id": "wappalyzer", "label": "Wappalyzer"},
        {"id": "shodan", "label": "Shodan"},
        {"id": "knockpy", "label": "Knockpy (subdomain brute-force)"},
        {"id": "kiterunner", "label": "Kiterunner (API discovery)"},
        {"id": "github_recon", "label": "GitHub recon"},
    ]
    return {"options": options, "allowed": list(PIPELINE_EXTENDED_TOOLS_ALLOWED)}
