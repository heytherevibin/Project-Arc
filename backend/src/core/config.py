"""
Arc Configuration Management

Centralized configuration using Pydantic Settings with environment variable support.
Supports .env files for development and environment variables for production.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    All sensitive values should be provided via environment variables
    or a .env file (development only).
    """
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )
    
    # =========================================================================
    # Application
    # =========================================================================
    APP_NAME: str = "Arc"
    APP_VERSION: str = "0.1.0"
    APP_ENV: Literal["development", "staging", "production"] = "development"
    DEBUG: bool = Field(default=False, description="Enable debug mode")
    
    # =========================================================================
    # API Server
    # =========================================================================
    API_HOST: str = Field(default="", description="API server host (set in .env)")
    API_PORT: int = Field(default=0, ge=0, le=65535, description="API server port (set in .env)")
    API_PREFIX: str = Field(default="/api/v1", description="API route prefix")
    API_WORKERS: int = Field(default=4, ge=1, description="Number of API workers")
    
    # CORS (from env only; comma-separated string → list in validator)
    CORS_ORIGINS: str | list[str] = Field(
        default="",
        description="Allowed CORS origins (comma-separated; set in .env)",
    )
    CORS_ORIGIN_REGEX: str = Field(
        default="",
        description="Optional regex for CORS origin matching (set in .env)",
    )
    
    # =========================================================================
    # Security & Authentication
    # =========================================================================
    JWT_SECRET_KEY: str = Field(
        ...,
        min_length=32,
        description="Secret key for JWT signing (minimum 32 characters)"
    )
    JWT_ALGORITHM: str = Field(default="HS256", description="JWT signing algorithm")
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=30,
        ge=5,
        description="Access token expiration in minutes"
    )
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = Field(
        default=7,
        ge=1,
        description="Refresh token expiration in days"
    )
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = Field(default=100, description="Requests per window")
    RATE_LIMIT_WINDOW_SECONDS: int = Field(default=60, description="Rate limit window")
    
    # =========================================================================
    # Neo4j Database
    # =========================================================================
    NEO4J_URI: str = Field(
        default="",
        description="Neo4j connection URI (set in .env, e.g. bolt://host:7687)",
    )
    NEO4J_USER: str = Field(default="", description="Neo4j username (set in .env)")
    NEO4J_PASSWORD: str = Field(..., description="Neo4j password (set in .env)")
    NEO4J_DATABASE: str = Field(default="", description="Neo4j database name (set in .env)")
    NEO4J_MAX_CONNECTION_POOL_SIZE: int = Field(
        default=50,
        ge=10,
        description="Maximum connection pool size"
    )
    
    # =========================================================================
    # Redis
    # =========================================================================
    REDIS_URL: str = Field(
        default="",
        description="Redis connection URL (set in .env)",
    )
    REDIS_MAX_CONNECTIONS: int = Field(default=10, ge=1)
    
    # =========================================================================
    # Elasticsearch (ELK Stack)
    # =========================================================================
    ELASTICSEARCH_URL: str = Field(
        default="",
        description="Elasticsearch URL (set in .env)",
    )
    ELASTICSEARCH_INDEX_PREFIX: str = Field(
        default="",
        description="Index prefix for Arc logs and data (set in .env)",
    )
    
    # =========================================================================
    # LLM Providers
    # =========================================================================
    LLM_PROVIDER: Literal["openai", "anthropic"] = Field(
        default="openai",
        description="Primary LLM provider"
    )
    
    # OpenAI
    OPENAI_API_KEY: str | None = Field(default=None, description="OpenAI API key (set in .env)")
    OPENAI_MODEL: str = Field(default="", description="OpenAI model name (set in .env)")
    OPENAI_MAX_TOKENS: int = Field(default=0, ge=0, description="OpenAI max tokens (set in .env)")
    
    # Anthropic
    ANTHROPIC_API_KEY: str | None = Field(default=None, description="Anthropic API key (set in .env)")
    ANTHROPIC_MODEL: str = Field(default="", description="Anthropic model name (set in .env)")
    ANTHROPIC_MAX_TOKENS: int = Field(default=0, ge=0, description="Anthropic max tokens (set in .env)")
    
    # =========================================================================
    # MCP Tool Servers (all from .env)
    # =========================================================================
    MCP_NAABU_URL: str = Field(default="", description="Naabu MCP server URL (set in .env)")
    MCP_HTTPX_URL: str = Field(default="", description="Httpx MCP server URL (set in .env)")
    MCP_SUBFINDER_URL: str = Field(default="", description="Subfinder MCP server URL (set in .env)")
    MCP_DNSX_URL: str = Field(default="", description="dnsx MCP server URL (set in .env)")
    MCP_KATANA_URL: str = Field(default="", description="Katana MCP server URL (set in .env)")
    MCP_NUCLEI_URL: str = Field(default="", description="Nuclei MCP server URL (set in .env)")
    # Extended recon (ports 8006–8012)
    MCP_GAU_URL: str = Field(default="", description="GAU URL discovery MCP server URL (set in .env)")
    MCP_KNOCKPY_URL: str = Field(default="", description="Knockpy subdomain brute-force MCP server URL (set in .env)")
    MCP_KITERUNNER_URL: str = Field(default="", description="Kiterunner API discovery MCP server URL (set in .env)")
    MCP_WAPPALYZER_URL: str = Field(default="", description="Wappalyzer tech fingerprinting MCP server URL (set in .env)")
    MCP_WHOIS_URL: str = Field(default="", description="Whois lookup MCP server URL (set in .env)")
    MCP_SHODAN_URL: str = Field(default="", description="Shodan passive recon MCP server URL (set in .env)")
    MCP_GITHUB_RECON_URL: str = Field(default="", description="GitHub recon MCP server URL (set in .env)")

    # =========================================================================
    # Scanning Configuration
    # =========================================================================
    SCAN_TIMEOUT_SECONDS: int = Field(
        default=3600,
        ge=60,
        description="Maximum scan duration in seconds"
    )
    SCAN_MAX_CONCURRENT: int = Field(
        default=5,
        ge=1,
        description="Maximum concurrent scans"
    )
    SCAN_RATE_LIMIT: int = Field(
        default=100,
        ge=1,
        description="Requests per second rate limit for scanning"
    )
    MONITORING_ENABLED: bool = Field(
        default=True,
        description="Enable continuous monitoring scheduler"
    )
    MONITORING_DEFAULT_INTERVAL_HOURS: float = Field(
        default=24.0,
        ge=1.0,
        le=168.0,
        description="Default re-scan interval in hours (1–168)"
    )
    # Comma-separated list of extended recon tools to run in pipeline (whois,gau,wappalyzer,shodan,knockpy,kiterunner,github_recon)
    PIPELINE_EXTENDED_TOOLS: str = Field(
        default="whois,gau,wappalyzer,shodan",
        description="Extended recon tools to run in pipeline (overridable via Settings API)"
    )

    # =========================================================================
    # Logging
    # =========================================================================
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Application log level"
    )
    LOG_FORMAT: Literal["json", "console"] = Field(
        default="json",
        description="Log output format"
    )
    LOG_TO_ELK: bool = Field(
        default=True,
        description="Send logs to Elasticsearch"
    )
    
    # =========================================================================
    # Validators
    # =========================================================================
    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: str | list[str]) -> list[str]:
        """Parse CORS origins from comma-separated string or list (from env)."""
        if isinstance(v, str):
            origins = [origin.strip() for origin in v.split(",") if origin.strip()]
        else:
            origins = list(v) if v else []
        return origins
    
    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        """Ensure JWT secret meets minimum security requirements."""
        if len(v) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters")
        return v
    
    # =========================================================================
    # Properties
    # =========================================================================
    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.APP_ENV == "development"
    
    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.APP_ENV == "production"
    
    @property
    def llm_api_key(self) -> str | None:
        """Get the API key for the configured LLM provider."""
        if self.LLM_PROVIDER == "openai":
            return self.OPENAI_API_KEY
        return self.ANTHROPIC_API_KEY
    
    @property
    def llm_model(self) -> str:
        """Get the model name for the configured LLM provider."""
        if self.LLM_PROVIDER == "openai":
            return self.OPENAI_MODEL
        return self.ANTHROPIC_MODEL


@lru_cache
def get_settings() -> Settings:
    """
    Get cached application settings.
    
    Settings are loaded once and cached for performance.
    Call `get_settings.cache_clear()` to reload settings.
    
    Returns:
        Settings: Application settings instance
    """
    return Settings()
