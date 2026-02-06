"""
Graph utilities for Neo4j result handling.
"""

from typing import Any


def node_to_dict(node: Any) -> dict[str, Any]:
    """
    Convert a Neo4j Node or dict-like record value to a plain dict.
    Use when building Pydantic models from execute_read/execute_write results
    to avoid serialization or subscript issues with raw Node types.
    """
    if node is None:
        return {}
    if isinstance(node, dict):
        return dict(node)
    if hasattr(node, "items"):
        return dict(node.items())
    try:
        return dict(node)
    except (TypeError, ValueError):
        return {}
