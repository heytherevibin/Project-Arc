"""
C2 (Command and Control) client integrations.

Native gRPC/API clients for C2 frameworks (e.g. Sliver).
Configuration via environment; no hardcoded endpoints.
"""

from c2.sliver_client import SliverClient, get_sliver_client

__all__ = ["SliverClient", "get_sliver_client"]
