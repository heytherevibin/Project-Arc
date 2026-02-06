# =============================================================================
# Arc Backend - Multi-stage Production Dockerfile
# =============================================================================
# Build: docker build -t arc-api --target production .
# Dev:   docker build -t arc-api-dev --target development .
# =============================================================================

# -----------------------------------------------------------------------------
# Base Stage: Common dependencies
# -----------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS base

# Prevent Python from writing pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd --gid 1000 arc \
    && useradd --uid 1000 --gid arc --shell /bin/bash --create-home arc

WORKDIR /app

# -----------------------------------------------------------------------------
# Builder Stage: Install dependencies
# -----------------------------------------------------------------------------
FROM base AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# -----------------------------------------------------------------------------
# Development Stage: Hot reload support
# -----------------------------------------------------------------------------
FROM base AS development

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install development dependencies
RUN pip install watchfiles pytest pytest-asyncio pytest-cov ruff mypy

# Copy source code
COPY --chown=arc:arc . .

ENV PYTHONPATH=/app/src

USER arc

EXPOSE 8080

CMD ["python", "-m", "uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8080", "--reload"]

# -----------------------------------------------------------------------------
# Production Stage: Optimized for deployment
# -----------------------------------------------------------------------------
FROM base AS production

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy only necessary source files
COPY --chown=arc:arc src/ ./src/

# So that "from api.xxx" / "from core.xxx" resolve (code lives under src/)
ENV PYTHONPATH=/app/src

# Switch to non-root user
USER arc

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080

# Single worker so BackgroundTasks (e.g. scan execution) run in-process; scale via replicas if needed
CMD ["python", "-m", "uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
