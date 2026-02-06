"""
Arc MCP Server - Main Entry Point

Runs all reconnaissance MCP servers concurrently.
"""

import asyncio
import os
import signal
import sys
from typing import NoReturn

import uvicorn


# Server configurations (aligned with backend config)
# Core recon: Naabu=8000, Httpx=8001, Subfinder=8002, dnsx=8003, Katana=8004, Nuclei=8005
# Extended recon: GAU=8006, Knockpy=8007, Kiterunner=8008, Wappalyzer=8009, Whois=8010, Shodan=8011, GitHub recon=8012
SERVERS = [
    # Core Recon (8000-8005)
    {"module": "servers.naabu_server:app", "port": 8000, "name": "naabu"},
    {"module": "servers.httpx_server:app", "port": 8001, "name": "httpx"},
    {"module": "servers.subfinder_server:app", "port": 8002, "name": "subfinder"},
    {"module": "servers.dnsx_server:app", "port": 8003, "name": "dnsx"},
    {"module": "servers.katana_server:app", "port": 8004, "name": "katana"},
    {"module": "servers.nuclei_server:app", "port": 8005, "name": "nuclei"},
    # Extended Recon (8006-8012)
    {"module": "servers.gau_server:app", "port": 8006, "name": "gau"},
    {"module": "servers.knockpy_server:app", "port": 8007, "name": "knockpy"},
    {"module": "servers.kiterunner_server:app", "port": 8008, "name": "kiterunner"},
    {"module": "servers.wappalyzer_server:app", "port": 8009, "name": "wappalyzer"},
    {"module": "servers.whois_server:app", "port": 8010, "name": "whois"},
    {"module": "servers.shodan_server:app", "port": 8011, "name": "shodan"},
    {"module": "servers.github_recon_server:app", "port": 8012, "name": "github_recon"},
    # Exploitation (8020-8022)
    {"module": "servers.metasploit_server:app", "port": 8020, "name": "metasploit"},
    {"module": "servers.sqlmap_server:app", "port": 8021, "name": "sqlmap"},
    # C2 (8030)
    {"module": "servers.sliver_server:app", "port": 8030, "name": "sliver"},
    # Vulnerability Scanning (8013-8014)
    {"module": "servers.gvm_server:app", "port": 8013, "name": "gvm"},
    {"module": "servers.nikto_server:app", "port": 8014, "name": "nikto"},
    # Exploitation (8022)
    {"module": "servers.commix_server:app", "port": 8022, "name": "commix"},
    # C2 (8031)
    {"module": "servers.havoc_server:app", "port": 8031, "name": "havoc"},
    # AD/Identity (8040-8043)
    {"module": "servers.bloodhound_server:app", "port": 8040, "name": "bloodhound"},
    {"module": "servers.certipy_server:app", "port": 8041, "name": "certipy"},
    {"module": "servers.impacket_server:app", "port": 8042, "name": "impacket"},
    {"module": "servers.crackmapexec_server:app", "port": 8043, "name": "crackmapexec"},
    # Utility (8050-8052)
    {"module": "servers.curl_server:app", "port": 8050, "name": "curl"},
    {"module": "servers.proxychains_server:app", "port": 8051, "name": "proxychains"},
    {"module": "servers.tor_server:app", "port": 8052, "name": "tor"},
]


async def run_server(config: dict) -> None:
    """Run a single uvicorn server."""
    server_config = uvicorn.Config(
        config["module"],
        host="0.0.0.0",
        port=config["port"],
        log_level="info",
        access_log=True,
    )
    server = uvicorn.Server(server_config)
    print(f"Starting {config['name']} server on port {config['port']}")
    await server.serve()


async def main() -> NoReturn:
    """Run all MCP servers concurrently."""
    print("Starting Arc MCP Reconnaissance Servers...")
    
    # Create tasks for all servers
    tasks = [asyncio.create_task(run_server(config)) for config in SERVERS]
    
    # Handle shutdown signals
    loop = asyncio.get_running_loop()
    
    def shutdown_handler() -> None:
        print("\nShutting down MCP servers...")
        for task in tasks:
            task.cancel()
    
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, shutdown_handler)
    
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        print("All servers stopped.")
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
