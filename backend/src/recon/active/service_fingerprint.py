"""
Service Fingerprinter

Enhanced service detection beyond basic port scanning.
Uses HTTP headers, banner grabbing, and protocol detection
to identify service versions accurately.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ServiceInfo:
    """Fingerprinted service details."""
    host: str
    port: int
    service_name: str = "unknown"
    version: str = ""
    banner: str = ""
    protocol: str = "tcp"
    http_title: str = ""
    http_server: str = ""
    tls_version: str = ""
    cert_issuer: str = ""
    cert_subject: str = ""
    technologies: list[str] = field(default_factory=list)
    confidence: float = 0.0  # 0-1


@dataclass
class FingerprintResult:
    """Result of service fingerprinting for a host."""
    host: str
    services: list[ServiceInfo] = field(default_factory=list)
    os_guess: str = ""


class ServiceFingerprinter:
    """
    Enhanced service fingerprinting using multiple data sources.

    Combines:
    - HTTP header analysis (Server, X-Powered-By, etc.)
    - TLS certificate inspection
    - Banner grabbing on common ports
    - Protocol-specific detection (SSH, FTP, SMTP, etc.)
    """

    # Well-known port → service/protocol mapping
    PORT_SERVICE_MAP: dict[int, str] = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 143: "imap",
        443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
        1433: "mssql", 1521: "oracle", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 5900: "vnc",
        6379: "redis", 8080: "http-proxy", 8443: "https-alt",
        9200: "elasticsearch", 27017: "mongodb",
    }

    def __init__(self, tool_executor: Any | None = None) -> None:
        self._executor = tool_executor

    async def fingerprint(
        self,
        host: str,
        ports: list[int] | None = None,
    ) -> FingerprintResult:
        """
        Fingerprint services on a host.

        Parameters
        ----------
        host  : target hostname or IP
        ports : specific ports to check (defaults to all open)
        """
        result = FingerprintResult(host=host)
        target_ports = ports or list(self.PORT_SERVICE_MAP.keys())

        for port in target_ports:
            service = await self._fingerprint_port(host, port)
            if service and service.service_name != "unknown":
                result.services.append(service)

        # Guess OS from service banners
        result.os_guess = self._guess_os(result.services)

        logger.info(
            "Fingerprinting complete",
            host=host,
            services=len(result.services),
            os=result.os_guess,
        )

        return result

    async def _fingerprint_port(self, host: str, port: int) -> ServiceInfo | None:
        """Fingerprint a single port."""
        service = ServiceInfo(host=host, port=port)

        # Use known port mapping as a starting point
        service.service_name = self.PORT_SERVICE_MAP.get(port, "unknown")

        # Use tool executor for deeper analysis if available
        if self._executor:
            try:
                if port in (80, 443, 8080, 8443):
                    await self._http_fingerprint(service)
                else:
                    await self._banner_grab(service)
            except Exception as exc:
                logger.debug("Fingerprint failed", host=host, port=port, error=str(exc))

        return service

    async def _http_fingerprint(self, service: ServiceInfo) -> None:
        """Fingerprint HTTP services using httpx probe data."""
        if not self._executor:
            return

        try:
            scheme = "https" if service.port in (443, 8443) else "http"
            url = f"{scheme}://{service.host}:{service.port}"

            result = await self._executor.execute("httpx", {
                "targets": [url],
                "status_code": True,
                "title": True,
                "server": True,
                "tech_detect": True,
            })

            if isinstance(result, dict):
                service.http_title = result.get("title", "")
                service.http_server = result.get("server", "")
                techs = result.get("technologies", [])
                service.technologies = techs if isinstance(techs, list) else []
                service.confidence = 0.9

        except Exception:
            pass

    async def _banner_grab(self, service: ServiceInfo) -> None:
        """Grab service banner using naabu or direct connection."""
        if not self._executor:
            return

        try:
            result = await self._executor.execute("naabu", {
                "host": service.host,
                "port": str(service.port),
                "version_detection": True,
            })

            if isinstance(result, dict):
                service.banner = result.get("banner", "")
                version = result.get("version", "")
                if version:
                    service.version = version
                    service.confidence = 0.7

        except Exception:
            pass

    @staticmethod
    def _guess_os(services: list[ServiceInfo]) -> str:
        """Guess OS from service banners and headers."""
        indicators: dict[str, int] = {"windows": 0, "linux": 0, "macos": 0}

        for s in services:
            banner = (s.banner + s.http_server).lower()
            if any(w in banner for w in ("windows", "iis", "microsoft")):
                indicators["windows"] += 1
            if any(w in banner for w in ("linux", "ubuntu", "debian", "centos", "apache", "nginx")):
                indicators["linux"] += 1
            if "macos" in banner or "darwin" in banner:
                indicators["macos"] += 1

        if not any(indicators.values()):
            return ""

        return max(indicators, key=indicators.get)  # type: ignore[arg-type]
