"""
Extended recon backend import verification.

Run with venv active: pytest tests/test_recon_extensions_imports.py
Verifies that extended recon tools and config can be imported (no mocks).
"""

import pytest


def test_extended_recon_config_has_mcp_urls():
    """Extended recon MCP URLs are present in config (from env)."""
    from core.config import get_settings

    s = get_settings()
    assert hasattr(s, "MCP_GAU_URL")
    assert hasattr(s, "MCP_WHOIS_URL")
    assert hasattr(s, "MCP_SHODAN_URL")
    assert hasattr(s, "MCP_GITHUB_RECON_URL")
    assert hasattr(s, "MCP_KNOCKPY_URL")
    assert hasattr(s, "MCP_KITERUNNER_URL")
    assert hasattr(s, "MCP_WAPPALYZER_URL")


def test_extended_recon_tools_import_and_have_mcp_url():
    """Extended recon tool classes import and expose mcp_url (from config)."""
    from recon.tools.gau import GauTool
    from recon.tools.whois import WhoisTool
    from recon.tools.shodan import ShodanTool
    from recon.tools.wappalyzer import WappalyzerTool

    assert GauTool().name == "gau"
    assert WhoisTool().name == "whois"
    assert ShodanTool().name == "shodan"
    assert WappalyzerTool().name == "wappalyzer"
    # mcp_url comes from get_settings(); may be empty in test env
    assert hasattr(GauTool(), "mcp_url")
    assert hasattr(WhoisTool(), "mcp_url")


def test_recon_tools_router_registered():
    """Recon tools API router can be imported and has extended recon routes."""
    from api.routes.recon_tools import router

    assert router is not None
    paths = [getattr(r, "path", "") for r in router.routes]
    assert any("gau" in p for p in paths)
    assert any("whois" in p for p in paths)


def test_pipeline_imports_enrichment_tools():
    """Recon pipeline has enrichment phase and storage helpers."""
    from recon.pipeline import ReconPipeline

    assert ReconPipeline is not None
    assert hasattr(ReconPipeline, "_phase_enrichment")
    assert hasattr(ReconPipeline, "_store_whois")
    assert hasattr(ReconPipeline, "_store_shodan_data")
