#!/usr/bin/env python3
"""
Verify extended recon backend imports and config.

Run from repo root or backend with venv active:
  cd backend && PYTHONPATH=src .venv/bin/python scripts/verify_recon_extensions.py
  cd backend && uv run python scripts/verify_recon_extensions.py  # if using uv with PYTHONPATH=src
"""

import sys
from pathlib import Path

# Ensure backend src is on path when run from backend/ or repo root
backend_src = Path(__file__).resolve().parent.parent / "src"
if backend_src.exists() and str(backend_src) not in sys.path:
    sys.path.insert(0, str(backend_src))


def main() -> None:
    from core.config import get_settings
    from recon.tools.gau import GauTool
    from recon.tools.knockpy import KnockpyTool
    from recon.tools.kiterunner import KiterunnerTool
    from recon.tools.wappalyzer import WappalyzerTool
    from recon.tools.whois import WhoisTool
    from recon.tools.shodan import ShodanTool
    from recon.tools.github_recon import GitHubReconTool
    from api.routes.recon_tools import router

    s = get_settings()
    assert hasattr(s, "MCP_GAU_URL")
    assert hasattr(s, "MCP_WHOIS_URL")
    assert hasattr(s, "MCP_SHODAN_URL")
    assert hasattr(s, "MCP_GITHUB_RECON_URL")
    assert GauTool().name == "gau"
    assert WhoisTool().name == "whois"
    assert ShodanTool().name == "shodan"
    assert router is not None
    print("Extended recon backend imports OK")


if __name__ == "__main__":
    main()
