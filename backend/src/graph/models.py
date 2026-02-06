"""
Arc Graph Models

Pydantic models for Neo4j nodes representing the attack surface.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from core.constants import Protocol, Severity


class BaseNode(BaseModel):
    """Base class for all graph nodes."""
    
    project_id: str = Field(..., description="Project identifier for multi-tenancy")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime | None = None
    
    def to_neo4j_properties(self) -> dict[str, Any]:
        """Convert model to Neo4j-compatible properties."""
        props = self.model_dump(exclude_none=True)
        # Convert datetime to ISO string
        if "created_at" in props:
            props["created_at"] = props["created_at"].isoformat()
        if "updated_at" in props and props["updated_at"]:
            props["updated_at"] = props["updated_at"].isoformat()
        return props


class DomainNode(BaseNode):
    """Root domain node - entry point for attack surface."""
    
    name: str = Field(..., description="Domain name (e.g., example.com)")
    registrar: str | None = None
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    organization: str | None = None
    country: str | None = None
    name_servers: list[str] = Field(default_factory=list)
    
    @field_validator("name")
    @classmethod
    def validate_domain_name(cls, v: str) -> str:
        """Normalize and validate domain name."""
        v = v.lower().strip()
        if not v:
            raise ValueError("Domain name cannot be empty")
        # Remove protocol if present
        for prefix in ["http://", "https://", "www."]:
            if v.startswith(prefix):
                v = v[len(prefix):]
        # Remove trailing slash
        v = v.rstrip("/")
        return v


class SubdomainNode(BaseNode):
    """Subdomain discovered during reconnaissance."""
    
    name: str = Field(..., description="Full subdomain name")
    has_dns_records: bool = False
    is_wildcard: bool = False
    discovery_source: str | None = Field(
        None,
        description="Tool/source that discovered this subdomain"
    )
    
    @field_validator("name")
    @classmethod
    def validate_subdomain(cls, v: str) -> str:
        """Normalize subdomain name."""
        return v.lower().strip()


class IPNode(BaseNode):
    """IP address node."""
    
    address: str = Field(..., description="IP address")
    version: int = Field(4, description="IP version (4 or 6)")
    is_internal: bool = False
    is_cdn: bool = False
    cdn_name: str | None = None
    asn: str | None = None
    asn_org: str | None = None
    country: str | None = None
    
    @field_validator("version")
    @classmethod
    def validate_version(cls, v: int) -> int:
        """Validate IP version."""
        if v not in (4, 6):
            raise ValueError("IP version must be 4 or 6")
        return v


class PortNode(BaseNode):
    """Open port discovered on a host."""
    
    number: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: Protocol = Field(Protocol.TCP, description="Port protocol")
    state: str = Field("open", description="Port state")
    
    @property
    def port_id(self) -> str:
        """Generate unique port identifier."""
        return f"{self.number}/{self.protocol.value}"


class ServiceNode(BaseNode):
    """Service running on a port."""
    
    name: str = Field(..., description="Service name (e.g., http, ssh)")
    product: str | None = Field(None, description="Product name")
    version: str | None = Field(None, description="Product version")
    banner: str | None = Field(None, description="Service banner")
    cpe: str | None = Field(None, description="Common Platform Enumeration")
    
    @field_validator("name")
    @classmethod
    def normalize_service_name(cls, v: str) -> str:
        """Normalize service name."""
        return v.lower().strip()


class URLNode(BaseNode):
    """URL/endpoint discovered during HTTP probing."""
    
    url: str = Field(..., description="Full URL")
    scheme: str = Field("https", description="URL scheme")
    host: str = Field(..., description="Hostname")
    path: str = Field("/", description="URL path")
    port: int | None = None
    status_code: int | None = None
    content_type: str | None = None
    content_length: int | None = None
    title: str | None = None
    server: str | None = None
    redirect_url: str | None = None
    is_live: bool = True
    
    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Normalize URL."""
        return v.strip().rstrip("/")


class EndpointNode(BaseNode):
    """API endpoint or web path."""
    
    path: str = Field(..., description="Endpoint path")
    method: str = Field("GET", description="HTTP method")
    base_url: str = Field(..., description="Base URL")
    has_parameters: bool = False
    parameter_count: int = 0
    category: str | None = Field(
        None,
        description="Endpoint category (api, auth, admin, etc.)"
    )
    
    @field_validator("method")
    @classmethod
    def normalize_method(cls, v: str) -> str:
        """Normalize HTTP method."""
        return v.upper()


class ParameterNode(BaseNode):
    """URL or form parameter."""
    
    name: str = Field(..., description="Parameter name")
    position: str = Field(
        "query",
        description="Parameter position (query, body, header, path)"
    )
    sample_value: str | None = None
    is_injectable: bool = False
    
    @field_validator("position")
    @classmethod
    def validate_position(cls, v: str) -> str:
        """Validate parameter position."""
        valid = {"query", "body", "header", "path", "cookie"}
        v = v.lower()
        if v not in valid:
            raise ValueError(f"Position must be one of: {valid}")
        return v


class TechnologyNode(BaseNode):
    """Technology detected on a target."""
    
    name: str = Field(..., description="Technology name")
    version: str | None = None
    categories: list[str] = Field(default_factory=list)
    confidence: int = Field(
        100,
        ge=0,
        le=100,
        description="Detection confidence (0-100)"
    )
    cpe: str | None = None
    detected_by: str | None = Field(
        None,
        description="Tool that detected this technology"
    )


class VulnerabilityNode(BaseNode):
    """Discovered vulnerability."""
    
    template_id: str = Field(..., description="Vulnerability template ID")
    name: str = Field(..., description="Vulnerability name")
    description: str | None = None
    severity: Severity = Field(Severity.UNKNOWN, description="Vulnerability severity")
    cvss_score: float | None = Field(None, ge=0, le=10)
    cve_id: str | None = None
    cwe_id: str | None = None
    matched_at: str | None = Field(None, description="URL where vulnerability was found")
    evidence: str | None = None
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    
    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: str | Severity) -> Severity:
        """Convert string severity to enum."""
        if isinstance(v, str):
            try:
                return Severity(v.lower())
            except ValueError:
                return Severity.UNKNOWN
        return v


class CVENode(BaseNode):
    """Common Vulnerabilities and Exposures entry."""
    
    cve_id: str = Field(..., description="CVE ID (e.g., CVE-2021-44228)")
    cvss_score: float | None = Field(None, ge=0, le=10)
    cvss_vector: str | None = None
    severity: Severity = Field(Severity.UNKNOWN)
    description: str | None = None
    published_date: datetime | None = None
    modified_date: datetime | None = None
    references: list[str] = Field(default_factory=list)
    
    @field_validator("cve_id")
    @classmethod
    def validate_cve_id(cls, v: str) -> str:
        """Validate CVE ID format."""
        v = v.upper().strip()
        if not v.startswith("CVE-"):
            raise ValueError("CVE ID must start with 'CVE-'")
        return v


class DNSRecordNode(BaseNode):
    """DNS record for a domain."""
    
    record_type: str = Field(..., description="DNS record type (A, AAAA, MX, etc.)")
    value: str = Field(..., description="Record value")
    ttl: int | None = None
    
    @field_validator("record_type")
    @classmethod
    def normalize_record_type(cls, v: str) -> str:
        """Normalize DNS record type."""
        return v.upper()


class CertificateNode(BaseNode):
    """TLS/SSL certificate."""
    
    subject_cn: str = Field(..., description="Subject Common Name")
    issuer: str | None = None
    serial_number: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    san: list[str] = Field(default_factory=list, description="Subject Alternative Names")
    signature_algorithm: str | None = None
    is_expired: bool = False
    is_self_signed: bool = False


class ScanNode(BaseNode):
    """Scan execution record."""
    
    scan_id: str = Field(..., description="Unique scan identifier")
    scan_type: str = Field(..., description="Type of scan")
    target: str = Field(..., description="Scan target")
    status: str = Field("pending", description="Scan status")
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: float | None = None
    findings_count: int = 0
    error_message: str | None = None
