#!/usr/bin/env bash
# =============================================================================
# Arc - Full clean rebuild (no cache)
# Use when images or config are stale and you want a fresh build.
#
# Rebuilds the full stack through Phase 2:
#   - api (core + extended recon tools config + monitoring scheduler)
#   - webapp (Mission Control UI)
#   - mcp-recon (core recon 8000-8005 + extended recon 8006-8012)
#   - neo4j, redis, elasticsearch, kibana, logstash
# Ensure .env has required vars (see .env.example). Optional: MCP_*_URL,
# MONITORING_ENABLED, PIPELINE_EXTENDED_TOOLS, SHODAN_API_KEY, GITHUB_TOKEN.
# =============================================================================
set -e
cd "$(dirname "$0")/.."

echo "Stopping and removing containers..."
docker compose down

echo "Rebuilding all images (no cache)..."
docker compose build --no-cache

echo "Starting services..."
docker compose up -d

echo "Done. Check: docker compose ps && docker compose logs -f --tail 20"
