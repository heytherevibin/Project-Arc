"""
Pipeline settings store (Neo4j).

Read/write pipeline extended tools list. Override from config when not set in DB.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.config import get_settings

if TYPE_CHECKING:
    from graph.client import Neo4jClient

# Allowed tool ids for pipeline extended recon (must match pipeline and MCP names)
PIPELINE_EXTENDED_TOOLS_ALLOWED = frozenset({
    "whois", "gau", "wappalyzer", "shodan",
    "knockpy", "kiterunner", "github_recon",
})
SETTINGS_KEY_PIPELINE_TOOLS = "pipeline_extended_tools"


async def get_pipeline_extended_tools(client: Neo4jClient) -> list[str]:
    """
    Return list of enabled pipeline extended tools.
    Reads from Neo4j AppSettings first; falls back to config PIPELINE_EXTENDED_TOOLS.
    """
    result = await client.execute_read(
        """
        MATCH (a:AppSettings { key: $key })
        RETURN a.value as value
        """,
        {"key": SETTINGS_KEY_PIPELINE_TOOLS},
    )
    if result and result[0].get("value"):
        raw = (result[0]["value"] or "").strip()
        if raw:
            tools = [t.strip().lower() for t in raw.split(",") if t.strip()]
            return [t for t in tools if t in PIPELINE_EXTENDED_TOOLS_ALLOWED]
    # Fallback to config
    config_val = (get_settings().PIPELINE_EXTENDED_TOOLS or "").strip()
    if not config_val:
        return []
    tools = [t.strip().lower() for t in config_val.split(",") if t.strip()]
    return [t for t in tools if t in PIPELINE_EXTENDED_TOOLS_ALLOWED]


async def set_pipeline_extended_tools(client: Neo4jClient, tools: list[str]) -> None:
    """Persist pipeline extended tools list to Neo4j (comma-separated)."""
    normalized = [t.strip().lower() for t in tools if t and t.strip().lower() in PIPELINE_EXTENDED_TOOLS_ALLOWED]
    value = ",".join(normalized)
    await client.execute_write(
        """
        MERGE (a:AppSettings { key: $key })
        ON CREATE SET a.value = $value
        ON MATCH SET a.value = $value
        """,
        {"key": SETTINGS_KEY_PIPELINE_TOOLS, "value": value},
    )
