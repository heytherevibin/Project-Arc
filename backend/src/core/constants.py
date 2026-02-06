"""
Arc Constants

Centralized definitions for enums, constants, and static values used across the framework.
"""

from enum import Enum, auto
from typing import Final


# =============================================================================
# Scan Constants
# =============================================================================

class ScanStatus(str, Enum):
    """Status values for scan operations."""
    
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    
    @property
    def is_terminal(self) -> bool:
        """Check if this status represents a terminal state."""
        return self in (
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
            ScanStatus.CANCELLED,
            ScanStatus.TIMEOUT,
        )
    
    @property
    def is_active(self) -> bool:
        """Check if this status represents an active state."""
        return self in (ScanStatus.RUNNING, ScanStatus.PAUSED)


class ScanType(str, Enum):
    """Types of reconnaissance scans."""
    
    # Discovery
    SUBDOMAIN_DISCOVERY = "subdomain_discovery"
    PORT_SCAN = "port_scan"
    DNS_RESOLUTION = "dns_resolution"
    
    # Probing
    HTTP_PROBE = "http_probe"
    SERVICE_FINGERPRINT = "service_fingerprint"
    
    # Crawling
    WEB_CRAWL = "web_crawl"
    API_DISCOVERY = "api_discovery"
    
    # Vulnerability
    VULNERABILITY_SCAN = "vulnerability_scan"
    TECHNOLOGY_DETECTION = "technology_detection"
    
    # Full Pipeline
    FULL_RECON = "full_recon"


class ScanPhase(str, Enum):
    """Phases within a reconnaissance pipeline."""
    
    INITIALIZATION = "initialization"
    SUBDOMAIN_ENUMERATION = "subdomain_enumeration"
    DNS_RESOLUTION = "dns_resolution"
    PORT_SCANNING = "port_scanning"
    HTTP_PROBING = "http_probing"
    TECHNOLOGY_DETECTION = "technology_detection"
    WEB_CRAWLING = "web_crawling"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    ENRICHMENT = "enrichment"
    FINALIZATION = "finalization"


# =============================================================================
# Severity Levels
# =============================================================================

class Severity(str, Enum):
    """Severity levels for vulnerabilities and findings."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"
    
    @property
    def numeric_value(self) -> int:
        """Get numeric value for sorting (higher = more severe)."""
        mapping = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
            Severity.UNKNOWN: 0,
        }
        return mapping[self]
    
    @classmethod
    def from_cvss(cls, cvss_score: float) -> "Severity":
        """Convert CVSS score to severity level."""
        if cvss_score >= 9.0:
            return cls.CRITICAL
        elif cvss_score >= 7.0:
            return cls.HIGH
        elif cvss_score >= 4.0:
            return cls.MEDIUM
        elif cvss_score >= 0.1:
            return cls.LOW
        return cls.INFO


# =============================================================================
# Agent Phases
# =============================================================================

class Phase(str, Enum):
    """Agent operational phases with escalation levels."""
    
    INFORMATIONAL = "informational"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    
    @property
    def requires_approval(self) -> bool:
        """Check if this phase requires human approval to enter."""
        return self in (
            Phase.EXPLOITATION,
            Phase.POST_EXPLOITATION,
            Phase.LATERAL_MOVEMENT,
            Phase.PERSISTENCE,
            Phase.EXFILTRATION,
        )
    
    @property
    def danger_level(self) -> int:
        """Get danger level for risk assessment (0-5)."""
        mapping = {
            Phase.INFORMATIONAL: 0,
            Phase.EXPLOITATION: 3,
            Phase.POST_EXPLOITATION: 4,
            Phase.LATERAL_MOVEMENT: 4,
            Phase.PERSISTENCE: 5,
            Phase.EXFILTRATION: 5,
        }
        return mapping[self]


# =============================================================================
# Asset Types
# =============================================================================

class AssetType(str, Enum):
    """Types of discovered assets."""
    
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    PORT = "port"
    SERVICE = "service"
    URL = "url"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    TECHNOLOGY = "technology"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"


class Protocol(str, Enum):
    """Network protocols."""
    
    TCP = "tcp"
    UDP = "udp"
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    SSH = "ssh"
    SMTP = "smtp"
    DNS = "dns"
    UNKNOWN = "unknown"


class HTTPMethod(str, Enum):
    """HTTP methods."""
    
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    CONNECT = "CONNECT"


# =============================================================================
# WebSocket Events
# =============================================================================

class WSEventType(str, Enum):
    """WebSocket event types for real-time updates."""
    
    # Connection
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    
    # Scan Events
    SCAN_STARTED = "scan_started"
    SCAN_PROGRESS = "scan_progress"
    SCAN_PHASE_CHANGED = "scan_phase_changed"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    
    # Discovery Events
    ASSET_DISCOVERED = "asset_discovered"
    VULNERABILITY_FOUND = "vulnerability_found"
    TECHNOLOGY_DETECTED = "technology_detected"
    
    # Agent Events
    AGENT_THINKING = "agent_thinking"
    AGENT_TOOL_START = "agent_tool_start"
    AGENT_TOOL_COMPLETE = "agent_tool_complete"
    AGENT_APPROVAL_REQUEST = "agent_approval_request"
    AGENT_RESPONSE = "agent_response"
    
    # System Events
    SYSTEM_NOTIFICATION = "system_notification"


# =============================================================================
# Tool Categories
# =============================================================================

class ToolCategory(str, Enum):
    """Categories for security tools."""
    
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    UTILITY = "utility"


# =============================================================================
# Neo4j Constants
# =============================================================================

class Neo4jLabel(str, Enum):
    """Neo4j node labels for the attack surface graph."""
    
    # Core Entities
    PROJECT = "Project"
    DOMAIN = "Domain"
    SUBDOMAIN = "Subdomain"
    IP = "IP"
    PORT = "Port"
    SERVICE = "Service"
    
    # Web Entities
    URL = "URL"
    ENDPOINT = "Endpoint"
    PARAMETER = "Parameter"
    TECHNOLOGY = "Technology"
    
    # Security Entities
    VULNERABILITY = "Vulnerability"
    CVE = "CVE"
    CWE = "CWE"
    CAPEC = "CAPEC"
    
    # DNS
    DNS_RECORD = "DNSRecord"
    CERTIFICATE = "Certificate"
    
    # Scan Tracking
    SCAN = "Scan"
    FINDING = "Finding"


class Neo4jRelationship(str, Enum):
    """Neo4j relationship types."""
    
    # Hierarchy
    BELONGS_TO = "BELONGS_TO"
    HAS_SUBDOMAIN = "HAS_SUBDOMAIN"
    HAS_PORT = "HAS_PORT"
    HAS_ENDPOINT = "HAS_ENDPOINT"
    HAS_PARAMETER = "HAS_PARAMETER"
    
    # Resolution
    RESOLVES_TO = "RESOLVES_TO"
    HAS_DNS_RECORD = "HAS_DNS_RECORD"
    HAS_CERTIFICATE = "HAS_CERTIFICATE"
    
    # Services
    RUNS_SERVICE = "RUNS_SERVICE"
    SERVES_URL = "SERVES_URL"
    USES_TECHNOLOGY = "USES_TECHNOLOGY"
    
    # Vulnerabilities
    HAS_VULNERABILITY = "HAS_VULNERABILITY"
    ASSOCIATED_CVE = "ASSOCIATED_CVE"
    MAPS_TO_CWE = "MAPS_TO_CWE"
    RELATED_CAPEC = "RELATED_CAPEC"
    FOUND_AT = "FOUND_AT"
    AFFECTS = "AFFECTS"
    
    # Scanning
    DISCOVERED_BY = "DISCOVERED_BY"


# =============================================================================
# Static Values
# =============================================================================

# Default ports for common services
DEFAULT_PORTS: Final[dict[str, list[int]]] = {
    "web": [80, 443, 8080, 8443, 8000, 8888],
    "database": [3306, 5432, 27017, 6379, 1433, 1521],
    "remote": [22, 23, 3389, 5900],
    "mail": [25, 587, 993, 995, 110, 143],
    "dns": [53],
    "file": [21, 445, 139],
}

# Common web technologies
COMMON_TECHNOLOGIES: Final[list[str]] = [
    "Apache",
    "Nginx",
    "IIS",
    "Node.js",
    "PHP",
    "Python",
    "Ruby",
    "Java",
    "ASP.NET",
    "WordPress",
    "Drupal",
    "Joomla",
    "React",
    "Angular",
    "Vue.js",
    "jQuery",
]

# CIDR ranges for internal networks (RFC 1918)
INTERNAL_NETWORK_RANGES: Final[list[str]] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
]

# Maximum values
MAX_SUBDOMAINS_PER_DOMAIN: Final[int] = 10000
MAX_PORTS_PER_HOST: Final[int] = 65535
MAX_URLS_PER_DOMAIN: Final[int] = 50000
MAX_VULNERABILITIES_PER_SCAN: Final[int] = 10000
