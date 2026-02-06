"""
Arc Reconnaissance Pipeline

Orchestrates reconnaissance tools in a structured pipeline.
"""

import asyncio
import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse, urlunparse

from core.config import get_settings
from core.constants import ScanPhase, ScanStatus, ScanType
from core.logging import LogContext, get_logger, log_scan_event
from graph.client import get_neo4j_client
from graph.settings_store import get_pipeline_extended_tools
from recon.orchestrators import (
    run_gau,
    run_github_recon,
    run_http_probe,
    run_kiterunner,
    run_knockpy,
    run_port_scan,
    run_shodan_enrichment,
    run_subdomain_enumeration,
    run_wappalyzer,
    run_web_crawl,
    run_whois,
)
from recon.tools.nuclei import NucleiTool


logger = get_logger(__name__)


def _normalize_url(url: str) -> str:
    """Normalize URL for matching: lowercase, strip trailing slash, default port."""
    if not url or not isinstance(url, str):
        return ""
    parsed = urlparse(url.strip())
    netloc = parsed.netloc.lower()
    if netloc.endswith(":80") and parsed.scheme == "http":
        netloc = netloc[:-3]
    if netloc.endswith(":443") and parsed.scheme == "https":
        netloc = netloc[:-4]
    path = parsed.path.rstrip("/") or "/"
    return urlunparse((parsed.scheme, netloc, path, parsed.params, parsed.query, ""))


def _url_candidates(matched_at: str) -> list[str]:
    """Build URL candidates for linking vulnerability to URL (exact + normalized variants)."""
    if not matched_at or not isinstance(matched_at, str):
        return []
    candidates = [matched_at.strip()]
    normalized = _normalize_url(matched_at)
    if normalized and normalized not in candidates:
        candidates.append(normalized)
    # With/without trailing slash
    if matched_at.rstrip("/") != matched_at and matched_at.rstrip("/") not in candidates:
        candidates.append(matched_at.rstrip("/"))
    return candidates


def _vulnerability_id(template_id: str, matched_at: str, project_id: str) -> str:
    """Generate a stable unique vulnerability id for deduplication and lookup."""
    payload = f"{template_id}:{matched_at or ''}:{project_id}"
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


class ReconPipeline:
    """
    Reconnaissance pipeline orchestrator.
    
    Executes tools in sequence:
    1. Subdomain enumeration (Subfinder)
    2. DNS resolution (dnsx)
    3. Port scanning (Naabu)
    4. HTTP probing (Httpx)
    5. Web crawling (Katana)
    6. Vulnerability scanning (Nuclei)
    
    Results are stored in Neo4j as the pipeline progresses.
    """
    
    def __init__(
        self,
        scan_id: str,
        project_id: str,
        target: str,
        scan_type: ScanType,
        options: dict[str, Any] | None = None,
    ) -> None:
        """
        Initialize the reconnaissance pipeline.
        
        Args:
            scan_id: Unique scan identifier
            project_id: Project this scan belongs to
            target: Target domain/IP/URL
            scan_type: Type of scan to perform
            options: Scan-specific options
        """
        self.scan_id = scan_id
        self.project_id = project_id
        self.target = target
        self.scan_type = scan_type
        self.options = options or {}
        
        self._client = get_neo4j_client()
        self._settings = get_settings()
        
        # Pipeline state
        self._current_phase = ScanPhase.INITIALIZATION
        self._progress = 0.0
        self._findings_count = 0
        self._errors: list[str] = []
        
        # Discovered data
        self._subdomains: list[str] = []
        self._resolved_ips: dict[str, list[str]] = {}
        self._open_ports: dict[str, list[int]] = {}
        self._live_urls: list[str] = []
        self._crawled_urls: list[str] = []
    
    async def execute(self) -> None:
        """Execute the full reconnaissance pipeline."""
        with LogContext(scan_id=self.scan_id, target=self.target):
            try:
                # Bootstrap first so scan always has at least the target, even if later phases fail
                await self._bootstrap_target_discovery()
                await self._start_scan()
                
                # Execute phases based on scan type
                if self.scan_type == ScanType.SUBDOMAIN_DISCOVERY:
                    await self._phase_subdomain_enumeration()()
                
                elif self.scan_type == ScanType.PORT_SCAN:
                    await self._phase_port_scanning()
                
                elif self.scan_type == ScanType.HTTP_PROBE:
                    await self._phase_http_probing()
                
                elif self.scan_type == ScanType.VULNERABILITY_SCAN:
                    await self._phase_vulnerability_scanning()
                
                elif self.scan_type == ScanType.FULL_RECON:
                    # Full pipeline (subdomain phase includes DNS resolution)
                    await self._phase_subdomain_enumeration()
                    await self._phase_port_scanning()
                    await self._phase_http_probing()
                    await self._phase_web_crawling()
                    await self._phase_vulnerability_scanning()
                    # Optional enrichment (Whois, GAU, Wappalyzer, Shodan) when MCP URLs are configured
                    if self.options.get("extended_recon", True):
                        await self._phase_enrichment()
                
                await self._complete_scan()
                
            except asyncio.CancelledError:
                logger.info("Scan cancelled", scan_id=self.scan_id)
                await self._update_status(ScanStatus.CANCELLED)
                raise
            
            except Exception as e:
                logger.exception("Scan failed", scan_id=self.scan_id, error=str(e))
                await self._fail_scan(str(e))
                raise
    
    async def _start_scan(self) -> None:
        """Mark scan as started."""
        now = datetime.now(timezone.utc).isoformat()
        
        await self._client.execute_write(
            """
            MATCH (s:Scan {scan_id: $scan_id})
            SET s.status = 'running',
                s.started_at = $started_at,
                s.phase = 'initialization'
            """,
            {"scan_id": self.scan_id, "started_at": now},
        )
        
        log_scan_event(logger, self.scan_id, "started", "initialization")
    
    async def _bootstrap_target_discovery(self) -> None:
        """Store the scan target as at least one discovery so results are never empty."""
        if not self.target or not self.target.strip():
            return
        now = datetime.now(timezone.utc).isoformat()
        await self._client.execute_write(
            """
            MERGE (d:Domain {name: $domain, project_id: $project_id})
            ON CREATE SET d.created_at = $created_at
            WITH d
            MERGE (s:Subdomain {name: $domain, project_id: $project_id})
            ON CREATE SET
                s.created_at = $created_at,
                s.discovery_source = 'target'
            WITH s
            MATCH (scan:Scan {scan_id: $scan_id})
            MERGE (scan)-[:DISCOVERED]->(s)
            WITH s
            MATCH (d:Domain {name: $domain, project_id: $project_id})
            MERGE (d)-[:HAS_SUBDOMAIN]->(s)
            """,
            {
                "domain": self.target.strip(),
                "project_id": self.project_id,
                "scan_id": self.scan_id,
                "created_at": now,
            },
        )
        self._findings_count += 1
    
    async def _update_phase(self, phase: ScanPhase, progress: float) -> None:
        """Update current scan phase and progress."""
        self._current_phase = phase
        self._progress = progress
        
        await self._client.execute_write(
            """
            MATCH (s:Scan {scan_id: $scan_id})
            SET s.phase = $phase,
                s.progress = $progress,
                s.findings_count = $findings
            """,
            {
                "scan_id": self.scan_id,
                "phase": phase.value,
                "progress": progress,
                "findings": self._findings_count,
            },
        )
        
        log_scan_event(logger, self.scan_id, "phase_changed", phase.value, progress)
    
    async def _update_status(self, status: ScanStatus) -> None:
        """Update scan status."""
        await self._client.execute_write(
            """
            MATCH (s:Scan {scan_id: $scan_id})
            SET s.status = $status
            """,
            {"scan_id": self.scan_id, "status": status.value},
        )
    
    async def _complete_scan(self) -> None:
        """Mark scan as completed."""
        now = datetime.now(timezone.utc).isoformat()
        
        # Calculate duration
        result = await self._client.execute_read(
            "MATCH (s:Scan {scan_id: $scan_id}) RETURN s.started_at as started",
            {"scan_id": self.scan_id},
        )
        
        duration = None
        if result and result[0]["started"]:
            start = datetime.fromisoformat(result[0]["started"].replace("Z", "+00:00"))
            end = datetime.now(timezone.utc)
            duration = (end - start).total_seconds()
        
        tool_errors_json = json.dumps(self._errors) if self._errors else None
        await self._client.execute_write(
            """
            MATCH (s:Scan {scan_id: $scan_id})
            SET s.status = 'completed',
                s.completed_at = $completed_at,
                s.duration_seconds = $duration,
                s.progress = 100.0,
                s.phase = 'finalization',
                s.findings_count = $findings,
                s.tool_errors = $tool_errors
            """,
            {
                "scan_id": self.scan_id,
                "completed_at": now,
                "duration": duration,
                "findings": self._findings_count,
                "tool_errors": tool_errors_json,
            },
        )
        
        log_scan_event(logger, self.scan_id, "completed", "finalization", 100.0)
    
    async def _fail_scan(self, error: str) -> None:
        """Mark scan as failed."""
        now = datetime.now(timezone.utc).isoformat()
        
        await self._client.execute_write(
            """
            MATCH (s:Scan {scan_id: $scan_id})
            SET s.status = 'failed',
                s.completed_at = $completed_at,
                s.error_message = $error
            """,
            {
                "scan_id": self.scan_id,
                "completed_at": now,
                "error": error[:500],
            },
        )
        
        log_scan_event(logger, self.scan_id, "failed", self._current_phase.value)
    
    # =========================================================================
    # Pipeline steps
    # =========================================================================
    
    async def _phase_subdomain_enumeration(self) -> None:
        """Subdomain enumeration (Subfinder, optional Knockpy) + DNS resolution (dnsx) via orchestrator."""
        await self._update_phase(ScanPhase.SUBDOMAIN_ENUMERATION, 10.0)
        logger.info("pipeline phase_subdomain_enumeration starting", scan_id=self.scan_id, target=self.target)
        enabled = await get_pipeline_extended_tools(self._client)
        options = dict(self.options)
        options["knockpy_enabled"] = "knockpy" in enabled and bool((self._settings.MCP_KNOCKPY_URL or "").strip())
        result = await run_subdomain_enumeration(self.target, options)
        if result.success and result.data:
            self._subdomains = result.data.get("subdomains", [])
            self._resolved_ips = result.data.get("resolved", {})
            await self._store_subdomains(self._subdomains)
            if self._resolved_ips:
                await self._store_dns_resolution(self._resolved_ips)
            self._findings_count += result.findings_delta
            logger.info("Subdomain enumeration complete", count=len(self._subdomains))
        else:
            logger.warning("Subdomain enumeration failed", error=result.error)
            self._errors.append(f"Subdomain/DNS: {result.error or 'unknown'}")
        await self._update_phase(ScanPhase.DNS_RESOLUTION, 25.0)
    
    async def _phase_dns_resolution(self) -> None:
        """Standalone DNS resolution (e.g. when subdomains already set). Normally subdomain phase does both."""
        if not self._subdomains:
            self._subdomains = [self.target]
        await self._update_phase(ScanPhase.DNS_RESOLUTION, 25.0)
        from recon.tools.dnsx import DnsxTool
        tool = DnsxTool()
        result = await tool.run(self._subdomains)
        await tool.close()
        if result.success and result.data:
            self._resolved_ips = result.data.get("resolved", {})
            await self._store_dns_resolution(self._resolved_ips)
        else:
            self._errors.append(f"dnsx: {result.error}")

    async def _phase_port_scanning(self) -> None:
        """Port scanning via orchestrator (Naabu)."""
        await self._update_phase(ScanPhase.PORT_SCANNING, 40.0)
        ips_to_scan = set()
        for _sub, ips in self._resolved_ips.items():
            ips_to_scan.update(ips)
        if not ips_to_scan:
            ips_to_scan = {self.target}
        result = await run_port_scan(list(ips_to_scan), target_fallback=self.target, options=self.options)
        if result.success and result.data:
            self._open_ports = result.data.get("ports", {})
            await self._store_ports(self._open_ports)
            self._findings_count += result.findings_delta
            logger.info("Port scanning complete", total_ports=result.findings_delta)
        else:
            logger.warning("Port scanning failed", error=result.error)
            self._errors.append(f"Naabu: {result.error}")
    
    async def _phase_http_probing(self) -> None:
        """HTTP probing via orchestrator (Httpx)."""
        await self._update_phase(ScanPhase.HTTP_PROBING, 55.0)
        result = await run_http_probe(
            self._subdomains,
            self._open_ports,
            self._resolved_ips,
            self.target,
            self.options,
        )
        if result.success and result.data:
            self._live_urls = result.data.get("live_urls", [])
            probed = result.data.get("probed", [])
            if probed:
                await self._store_urls(probed)
            self._findings_count += result.findings_delta
            logger.info("HTTP probing complete", live_count=len(self._live_urls))
        else:
            logger.warning("HTTP probing failed", error=result.error)
            self._errors.append(f"Httpx: {result.error}")

    async def _phase_web_crawling(self) -> None:
        """Web crawling via orchestrator (Katana)."""
        await self._update_phase(ScanPhase.WEB_CRAWLING, 70.0)
        if not self._live_urls:
            logger.info("No live URLs to crawl")
            return
        result = await run_web_crawl(self._live_urls, self.options)
        if result.success and result.data:
            self._crawled_urls = result.data.get("discovered_urls", [])
            await self._store_endpoints(self._crawled_urls)
            self._findings_count += result.findings_delta
            logger.info("Web crawling complete", discovered_count=len(self._crawled_urls))
        else:
            logger.warning("Web crawling failed", error=result.error)
            self._errors.append(f"Katana: {result.error}")
    
    async def _phase_vulnerability_scanning(self) -> None:
        """Vulnerability scanning using Nuclei."""
        await self._update_phase(ScanPhase.VULNERABILITY_SCANNING, 85.0)
        
        # Combine live URLs and crawled endpoints
        urls_to_scan = list(set(self._live_urls + self._crawled_urls))
        
        if not urls_to_scan:
            urls_to_scan = [f"https://{self.target}"]
        
        tool = NucleiTool()
        result = await tool.run(urls_to_scan)
        
        if result.success and result.data:
            vulnerabilities = result.data.get("vulnerabilities", [])
            
            # Store in Neo4j
            await self._store_vulnerabilities(vulnerabilities)
            
            self._findings_count += len(vulnerabilities)
            
            logger.info(
                "Vulnerability scanning complete",
                vulnerabilities_found=len(vulnerabilities),
            )
        else:
            logger.warning(
                "Vulnerability scanning failed",
                error=result.error,
            )
            self._errors.append(f"Nuclei: {result.error}")
    
    async def _phase_enrichment(self) -> None:
        """Optional enrichment: tools from Settings (Whois, GAU, Wappalyzer, Shodan, Knockpy, Kiterunner, GitHub). Runs only when enabled in settings and MCP URL is configured."""
        settings = self._settings
        enabled = await get_pipeline_extended_tools(self._client)
        progress = 88.0
        step = 3.0

        # Whois (orchestrator)
        if "whois" in enabled and (settings.MCP_WHOIS_URL or "").strip():
            await self._update_phase(ScanPhase.ENRICHMENT, progress)
            progress += step
            result = await run_whois(self.target, self.options)
            if result.success and result.data.get("whois"):
                await self._store_whois(
                    self.target,
                    result.data.get("whois", {}),
                    result.data.get("raw"),
                )
            elif result.error:
                self._errors.append(f"Whois: {result.error}")

        # GAU (orchestrator)
        if "gau" in enabled and (settings.MCP_GAU_URL or "").strip():
            await self._update_phase(ScanPhase.ENRICHMENT, progress)
            progress += step
            result = await run_gau(self.target, self.options)
            if result.success and result.data.get("urls"):
                await self._store_urls_from_gau(result.data["urls"])
                self._findings_count += result.findings_delta
            elif result.error:
                self._errors.append(f"GAU: {result.error}")

        # Wappalyzer (orchestrator)
        if "wappalyzer" in enabled and (settings.MCP_WAPPALYZER_URL or "").strip() and self._live_urls:
            await self._update_phase(ScanPhase.ENRICHMENT, progress)
            progress += step
            result = await run_wappalyzer(self._live_urls[:5], self.options)
            if result.success and result.data.get("url_technologies"):
                await self._store_technologies(result.data["url_technologies"])

        # Shodan (orchestrator)
        if "shodan" in enabled and (settings.MCP_SHODAN_URL or "").strip():
            await self._update_phase(ScanPhase.ENRICHMENT, progress)
            progress += step
            ips = set()
            for _sub, ip_list in self._resolved_ips.items():
                ips.update(ip_list)
            result = await run_shodan_enrichment(list(ips), self.options)
            if result.success and result.data.get("ip_data"):
                await self._store_shodan_data(result.data["ip_data"])

        # Knockpy (orchestrator) — optional standalone run; subdomain phase can also run it
        if "knockpy" in enabled and (settings.MCP_KNOCKPY_URL or "").strip():
            await self._update_phase(ScanPhase.ENRICHMENT, progress)
            progress += step
            result = await run_knockpy(self.target, self.options)
            if result.success and result.data.get("subdomains"):
                await self._store_subdomains(result.data["subdomains"], discovery_source="knockpy")
                self._findings_count += result.findings_delta
            elif result.error:
                self._errors.append(f"Knockpy: {result.error}")

        # Kiterunner (orchestrator)
        if "kiterunner" in enabled and (settings.MCP_KITERUNNER_URL or "").strip() and self._live_urls:
            await self._update_phase(ScanPhase.ENRICHMENT, progress)
            progress += step
            result = await run_kiterunner(self._live_urls[:3], self.options)
            if result.success and result.data.get("endpoints_by_url"):
                for item in result.data["endpoints_by_url"]:
                    await self._store_kiterunner_endpoints(item["base_url"], item["endpoints"])
                self._findings_count += result.findings_delta
            elif result.error:
                self._errors.append(f"Kiterunner: {result.error}")

        # GitHub recon (orchestrator)
        if "github_recon" in enabled and (settings.MCP_GITHUB_RECON_URL or "").strip():
            await self._update_phase(ScanPhase.ENRICHMENT, min(progress + step, 98.0))
            result = await run_github_recon(self.target, query_template=f"org:{self.target}", options=self.options)
            if result.success and result.data:
                await self._store_github_repos(result.data.get("repos", []), self.target)
                await self._store_github_findings(result.data.get("findings", []))
                self._findings_count += result.findings_delta
            elif result.error:
                self._errors.append(f"GitHub recon: {result.error}")
    
    # =========================================================================
    # Data Storage
    # =========================================================================
    
    async def _store_subdomains(self, subdomains: list[str], discovery_source: str = "subfinder") -> None:
        """Store discovered subdomains in Neo4j. discovery_source: e.g. 'subfinder', 'knockpy'."""
        if not subdomains:
            return
        
        query = """
        UNWIND $subdomains as subdomain
        MERGE (s:Subdomain {name: subdomain, project_id: $project_id})
        ON CREATE SET
            s.created_at = $created_at,
            s.discovery_source = $discovery_source
        ON MATCH SET s.discovery_source = $discovery_source
        WITH s
        MATCH (scan:Scan {scan_id: $scan_id})
        MERGE (scan)-[:DISCOVERED]->(s)
        WITH s
        MATCH (d:Domain {name: $domain, project_id: $project_id})
        MERGE (d)-[:HAS_SUBDOMAIN]->(s)
        """
        
        await self._client.execute_write(
            query,
            {
                "subdomains": subdomains,
                "project_id": self.project_id,
                "scan_id": self.scan_id,
                "domain": self.target,
                "discovery_source": discovery_source[:50],
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        
        self._findings_count += len(subdomains)
    
    async def _store_dns_resolution(self, resolved: dict[str, list[str]]) -> None:
        """Store DNS resolution results in Neo4j."""
        if not resolved:
            return
        
        for subdomain, ips in resolved.items():
            for ip in ips:
                query = """
                MATCH (s:Subdomain {name: $subdomain, project_id: $project_id})
                MERGE (i:IP {address: $ip, project_id: $project_id})
                ON CREATE SET
                    i.created_at = $created_at
                MERGE (s)-[:RESOLVES_TO]->(i)
                WITH i
                MATCH (scan:Scan {scan_id: $scan_id})
                MERGE (scan)-[:DISCOVERED]->(i)
                """
                
                await self._client.execute_write(
                    query,
                    {
                        "subdomain": subdomain,
                        "ip": ip,
                        "project_id": self.project_id,
                        "scan_id": self.scan_id,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    },
                )
    
    async def _store_ports(self, ports: dict[str, list[int]]) -> None:
        """Store discovered ports in Neo4j."""
        if not ports:
            return
        
        for ip, port_list in ports.items():
            for port in port_list:
                query = """
                MATCH (i:IP {address: $ip, project_id: $project_id})
                MERGE (p:Port {number: $port, ip: $ip, project_id: $project_id})
                ON CREATE SET
                    p.protocol = 'tcp',
                    p.state = 'open',
                    p.created_at = $created_at
                MERGE (i)-[:HAS_PORT]->(p)
                WITH p
                MATCH (scan:Scan {scan_id: $scan_id})
                MERGE (scan)-[:DISCOVERED]->(p)
                """
                
                await self._client.execute_write(
                    query,
                    {
                        "ip": ip,
                        "port": port,
                        "project_id": self.project_id,
                        "scan_id": self.scan_id,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    },
                )
    
    async def _store_urls(self, probed: list[dict]) -> None:
        """Store probed URLs in Neo4j."""
        if not probed:
            return
        
        for probe_result in probed:
            query = """
            MERGE (u:URL {url: $url, project_id: $project_id})
            ON CREATE SET
                u.status_code = $status_code,
                u.title = $title,
                u.content_type = $content_type,
                u.content_length = $content_length,
                u.server = $server,
                u.is_live = true,
                u.created_at = $created_at
            ON MATCH SET
                u.status_code = $status_code,
                u.title = $title,
                u.content_type = $content_type,
                u.content_length = $content_length,
                u.server = $server,
                u.is_live = true
            WITH u
            MATCH (scan:Scan {scan_id: $scan_id})
            MERGE (scan)-[:DISCOVERED]->(u)
            """
            
            await self._client.execute_write(
                query,
                {
                    "url": probe_result.get("url"),
                    "status_code": probe_result.get("status_code"),
                    "title": probe_result.get("title"),
                    "content_type": probe_result.get("content_type"),
                    "content_length": probe_result.get("content_length"),
                    "server": probe_result.get("server"),
                    "project_id": self.project_id,
                    "scan_id": self.scan_id,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
            )
    
    async def _store_endpoints(self, urls: list[str]) -> None:
        """Store crawled endpoints in Neo4j."""
        if not urls:
            return
        
        for url in urls:
            query = """
            MERGE (e:Endpoint {url: $url, project_id: $project_id})
            ON CREATE SET
                e.created_at = $created_at,
                e.discovery_source = 'katana'
            WITH e
            MATCH (scan:Scan {scan_id: $scan_id})
            MERGE (scan)-[:DISCOVERED]->(e)
            """
            
            await self._client.execute_write(
                query,
                {
                    "url": url,
                    "project_id": self.project_id,
                    "scan_id": self.scan_id,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
            )
    
    async def _store_vulnerabilities(self, vulnerabilities: list[dict]) -> None:
        """Store discovered vulnerabilities in Neo4j with stable id and URL linking."""
        if not vulnerabilities:
            return
        
        for vuln in vulnerabilities:
            template_id = vuln.get("template_id", "unknown")
            matched_at = vuln.get("matched_at") or ""
            vulnerability_id = _vulnerability_id(template_id, matched_at, self.project_id)
            url_candidates = _url_candidates(matched_at)
            if not url_candidates:
                url_candidates = [""]
            
            query = """
            MERGE (v:Vulnerability {
                template_id: $template_id,
                matched_at: $matched_at,
                project_id: $project_id
            })
            ON CREATE SET
                v.vulnerability_id = $vulnerability_id,
                v.name = $name,
                v.severity = $severity,
                v.created_at = $created_at,
                v.description = $description,
                v.evidence = $evidence
            ON MATCH SET
                v.vulnerability_id = $vulnerability_id,
                v.name = $name,
                v.severity = $severity,
                v.description = $description,
                v.evidence = $evidence
            WITH v
            MATCH (scan:Scan {scan_id: $scan_id})
            MERGE (scan)-[:DISCOVERED]->(v)
            WITH v
            MATCH (u:URL)
            WHERE u.project_id = $project_id AND u.url IN $url_candidates
            MERGE (u)-[:HAS_VULNERABILITY]->(v)
            """
            
            await self._client.execute_write(
                query,
                {
                    "vulnerability_id": vulnerability_id,
                    "template_id": template_id,
                    "name": vuln.get("name", "Unknown Vulnerability"),
                    "severity": vuln.get("severity", "unknown"),
                    "matched_at": matched_at,
                    "description": vuln.get("description"),
                    "evidence": vuln.get("evidence"),
                    "project_id": self.project_id,
                    "scan_id": self.scan_id,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "url_candidates": url_candidates,
                },
            )

    async def _store_whois(self, domain: str, whois_dict: dict[str, Any], raw: str | None) -> None:
        """Store WHOIS data for a domain. Domain must exist."""
        if not domain or not domain.strip():
            return
        now = datetime.now(timezone.utc).isoformat()
        raw_str = (raw or json.dumps(whois_dict or {}))[:10000]
        await self._client.execute_write(
            """
            MERGE (d:Domain {name: $domain, project_id: $project_id})
            ON CREATE SET d.created_at = $created_at
            WITH d
            MERGE (w:WhoisData {domain_name: $domain, project_id: $project_id})
            ON CREATE SET
                w.raw = $raw,
                w.created_at = $created_at
            ON MATCH SET w.raw = $raw
            WITH w
            MATCH (d:Domain {name: $domain, project_id: $project_id})
            MERGE (d)-[:HAS_WHOIS]->(w)
            WITH w
            MATCH (scan:Scan {scan_id: $scan_id})
            MERGE (scan)-[:DISCOVERED]->(w)
            """,
            {
                "domain": domain.strip(),
                "project_id": self.project_id,
                "scan_id": self.scan_id,
                "raw": raw_str,
                "created_at": now,
            },
        )

    async def _store_urls_from_gau(self, urls: list[str]) -> None:
        """Store GAU-discovered URLs in Neo4j. Links to Domain and Scan."""
        if not urls:
            return
        now = datetime.now(timezone.utc).isoformat()
        for url in urls[:2000]:
            url_str = (url or "").strip()
            if not url_str or not url_str.startswith(("http://", "https://")):
                continue
            await self._client.execute_write(
                """
                MERGE (u:URL {url: $url, project_id: $project_id})
                ON CREATE SET
                    u.discovery_source = 'gau',
                    u.is_live = false,
                    u.created_at = $created_at
                WITH u
                MATCH (scan:Scan {scan_id: $scan_id})
                MERGE (scan)-[:DISCOVERED]->(u)
                WITH u
                MERGE (d:Domain {name: $domain, project_id: $project_id})
                ON CREATE SET d.created_at = $created_at
                WITH u, d
                MERGE (d)-[:HAS_URL]->(u)
                """,
                {
                    "url": url_str,
                    "project_id": self.project_id,
                    "scan_id": self.scan_id,
                    "domain": self.target,
                    "created_at": now,
                },
            )
        self._findings_count += min(len(urls), 2000)

    async def _store_technologies(self, url_techs: list[dict[str, Any]]) -> None:
        """Store Wappalyzer technologies per URL. Links URL to Technology."""
        if not url_techs:
            return
        now = datetime.now(timezone.utc).isoformat()
        for item in url_techs:
            url_str = (item.get("url") or "").strip()
            techs = item.get("technologies") or []
            if not url_str or not techs:
                continue
            for t in techs:
                name = (t.get("name") or t.get("category") or "unknown") if isinstance(t, dict) else str(t)
                category = t.get("category", "unknown") if isinstance(t, dict) else "unknown"
                version = (t.get("version") or "") if isinstance(t, dict) else ""
                await self._client.execute_write(
                    """
                    MERGE (u:URL {url: $url, project_id: $project_id})
                    ON CREATE SET u.created_at = $created_at
                    WITH u
                    MERGE (tech:Technology {name: $name, project_id: $project_id})
                    ON CREATE SET
                        tech.version = $version,
                        tech.categories = [$category],
                        tech.created_at = $created_at
                    ON MATCH SET tech.version = $version
                    WITH u, tech
                    MERGE (u)-[:USES_TECHNOLOGY]->(tech)
                    WITH tech
                    MATCH (scan:Scan {scan_id: $scan_id})
                    MERGE (scan)-[:DISCOVERED]->(tech)
                    """,
                    {
                        "url": url_str,
                        "project_id": self.project_id,
                        "scan_id": self.scan_id,
                        "name": name[:200],
                        "version": str(version)[:100],
                        "category": str(category)[:100],
                        "created_at": now,
                    },
                )

    async def _store_shodan_data(self, ip_data: dict[str, dict]) -> None:
        """Store Shodan/InternetDB data per IP. Links IP to ShodanData."""
        if not ip_data:
            return
        now = datetime.now(timezone.utc).isoformat()
        for ip, data in ip_data.items():
            if not ip or not isinstance(data, dict):
                continue
            # Store as JSON string for Neo4j (no nested dict in node props)
            data_json = json.dumps(data)[:15000]
            await self._client.execute_write(
                """
                MERGE (i:IP {address: $ip, project_id: $project_id})
                ON CREATE SET i.created_at = $created_at
                WITH i
                MERGE (s:ShodanData {ip: $ip, project_id: $project_id})
                ON CREATE SET
                    s.data_json = $data_json,
                    s.created_at = $created_at
                ON MATCH SET s.data_json = $data_json
                WITH i, s
                MERGE (i)-[:HAS_SHODAN_DATA]->(s)
                WITH s
                MATCH (scan:Scan {scan_id: $scan_id})
                MERGE (scan)-[:DISCOVERED]->(s)
                """,
                {
                    "ip": ip.strip(),
                    "project_id": self.project_id,
                    "scan_id": self.scan_id,
                    "data_json": data_json,
                    "created_at": now,
                },
            )

    async def _store_kiterunner_endpoints(self, base_url: str, endpoints: list[dict[str, Any]]) -> None:
        """Store Kiterunner API endpoints. Links URL to ApiEndpoint, Scan to ApiEndpoint."""
        if not base_url or not endpoints:
            return
        base_url = base_url.strip().rstrip("/") or base_url
        now = datetime.now(timezone.utc).isoformat()
        for ep in endpoints[:500]:
            method = (ep.get("method") or "GET").upper()[:10]
            path = (ep.get("path") or "").strip()[:2000]
            if not path:
                continue
            await self._client.execute_write(
                """
                MERGE (u:URL {url: $base_url, project_id: $project_id})
                ON CREATE SET u.created_at = $created_at
                WITH u
                MERGE (a:ApiEndpoint {base_url: $base_url, path: $path, method: $method, project_id: $project_id})
                ON CREATE SET a.created_at = $created_at
                WITH u, a
                MERGE (u)-[:HAS_ENDPOINT]->(a)
                WITH a
                MATCH (scan:Scan {scan_id: $scan_id})
                MERGE (scan)-[:DISCOVERED]->(a)
                """,
                {
                    "base_url": base_url,
                    "path": path,
                    "method": method,
                    "project_id": self.project_id,
                    "scan_id": self.scan_id,
                    "created_at": now,
                },
            )
        self._findings_count += min(len(endpoints), 500)

    async def _store_github_repos(self, repos: list[dict[str, Any]], domain_context: str) -> None:
        """Store GitHub repos from recon. Links Domain to GitHubRepo, Scan to GitHubRepo."""
        if not repos or not domain_context:
            return
        domain = domain_context.strip()
        now = datetime.now(timezone.utc).isoformat()
        for r in repos[:200]:
            full_name = (r.get("full_name") or "").strip()
            if not full_name:
                continue
            html_url = (r.get("html_url") or "")[:2000]
            description = (r.get("description") or "")[:1000] if r.get("description") else ""
            updated_at = (r.get("updated_at") or "")[:50]
            await self._client.execute_write(
                """
                MERGE (d:Domain {name: $domain, project_id: $project_id})
                ON CREATE SET d.created_at = $created_at
                WITH d
                MERGE (g:GitHubRepo {full_name: $full_name, project_id: $project_id})
                ON CREATE SET
                    g.html_url = $html_url,
                    g.description = $description,
                    g.updated_at = $updated_at,
                    g.created_at = $created_at
                ON MATCH SET
                    g.html_url = $html_url,
                    g.description = $description,
                    g.updated_at = $updated_at
                WITH d, g
                MERGE (d)-[:HAS_GITHUB_REPO]->(g)
                WITH g
                MATCH (scan:Scan {scan_id: $scan_id})
                MERGE (scan)-[:DISCOVERED]->(g)
                """,
                {
                    "domain": domain,
                    "full_name": full_name,
                    "project_id": self.project_id,
                    "scan_id": self.scan_id,
                    "html_url": html_url,
                    "description": description,
                    "updated_at": updated_at,
                    "created_at": now,
                },
            )
        self._findings_count += min(len(repos), 200)

    async def _store_github_findings(self, findings: list[dict[str, Any]]) -> None:
        """Store GitHub code search findings. Scan discovers GitHubFinding."""
        if not findings:
            return
        now = datetime.now(timezone.utc).isoformat()
        for f in findings[:200]:
            repo_full_name = (f.get("repository") or "").strip()[:500]
            path = (f.get("path") or "").strip()[:1000]
            html_url = (f.get("html_url") or "")[:2000]
            if not repo_full_name or not path:
                continue
            await self._client.execute_write(
                """
                MERGE (f:GitHubFinding {repo_full_name: $repo_full_name, path: $path, project_id: $project_id})
                ON CREATE SET
                    f.html_url = $html_url,
                    f.created_at = $created_at
                ON MATCH SET f.html_url = $html_url
                WITH f
                MATCH (scan:Scan {scan_id: $scan_id})
                MERGE (scan)-[:DISCOVERED]->(f)
                """,
                {
                    "repo_full_name": repo_full_name,
                    "path": path,
                    "project_id": self.project_id,
                    "scan_id": self.scan_id,
                    "html_url": html_url,
                    "created_at": now,
                },
            )
        self._findings_count += min(len(findings), 200)
