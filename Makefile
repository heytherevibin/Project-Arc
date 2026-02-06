# =============================================================================
# Arc - Enterprise Red Team Framework
# Build & Operations Makefile
# =============================================================================

.DEFAULT_GOAL := help
SHELL := /bin/bash
COMPOSE := docker compose
COMPOSE_DEV := $(COMPOSE) -f docker-compose.yml -f docker-compose.dev.yml
COMPOSE_LAB := $(COMPOSE) -f docker-compose.yml -f docker-compose.lab.yml

# Colors
GREEN  := \033[0;32m
YELLOW := \033[0;33m
RED    := \033[0;31m
CYAN   := \033[0;36m
NC     := \033[0m

# =============================================================================
# Help
# =============================================================================
.PHONY: help
help: ## Show this help message
	@echo ""
	@echo "$(CYAN)Arc - Enterprise Red Team Framework$(NC)"
	@echo "$(CYAN)====================================$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""

# =============================================================================
# Build
# =============================================================================
.PHONY: build build-api build-webapp build-mcp
build: ## Build all Docker images
	@echo "$(CYAN)[Arc]$(NC) Building all services..."
	$(COMPOSE) build

build-api: ## Build only the API image
	$(COMPOSE) build api

build-webapp: ## Build only the webapp image
	$(COMPOSE) build webapp

build-mcp: ## Build only the MCP recon image
	$(COMPOSE) build mcp-recon

# =============================================================================
# Run (Production)
# =============================================================================
.PHONY: up down restart status logs
up: ## Start all services (production)
	@echo "$(CYAN)[Arc]$(NC) Starting production stack..."
	$(COMPOSE) up -d
	@echo "$(GREEN)[Arc]$(NC) Stack is up. API: http://localhost:$${API_PORT:-8080}  UI: http://localhost:$${WEBAPP_PORT:-3000}"

down: ## Stop all services and remove containers
	@echo "$(YELLOW)[Arc]$(NC) Stopping all services..."
	$(COMPOSE) down

restart: down up ## Restart all services

status: ## Show service status
	$(COMPOSE) ps

logs: ## Tail logs from all services
	$(COMPOSE) logs -f --tail=100

# =============================================================================
# Development
# =============================================================================
.PHONY: dev dev-down dev-logs dev-restart
dev: ## Start development stack (hot-reload, no ELK)
	@echo "$(CYAN)[Arc]$(NC) Starting development stack..."
	$(COMPOSE_DEV) up -d
	@echo "$(GREEN)[Arc]$(NC) Dev stack is up. API: http://localhost:$${API_PORT:-8080}  UI: http://localhost:$${WEBAPP_PORT:-3000}"

dev-down: ## Stop development stack
	$(COMPOSE_DEV) down

dev-logs: ## Tail development logs
	$(COMPOSE_DEV) logs -f --tail=100

dev-restart: dev-down dev ## Restart development stack

# =============================================================================
# Lab Environment (Vulnerable targets for testing)
# =============================================================================
.PHONY: lab lab-down lab-status
lab: ## Start lab environment with vulnerable targets
	@echo "$(CYAN)[Arc]$(NC) Starting lab environment..."
	$(COMPOSE_LAB) up -d
	@echo "$(GREEN)[Arc]$(NC) Lab targets are up."
	@echo "  DVWA:       http://localhost:8880"
	@echo "  Juice Shop: http://localhost:8881"
	@echo "  WebGoat:    http://localhost:8882"

lab-down: ## Stop lab environment
	$(COMPOSE_LAB) down

lab-status: ## Show lab service status
	$(COMPOSE_LAB) ps

# =============================================================================
# Database Operations
# =============================================================================
.PHONY: db-migrate db-reset db-shell neo4j-shell redis-cli
db-migrate: ## Run PostgreSQL migrations via Alembic
	@echo "$(CYAN)[Arc]$(NC) Running database migrations..."
	$(COMPOSE) exec api alembic upgrade head

db-reset: ## Reset PostgreSQL database (DESTRUCTIVE)
	@echo "$(RED)[Arc]$(NC) Resetting PostgreSQL database..."
	$(COMPOSE) exec postgres psql -U $${POSTGRES_USER:-arc} -d $${POSTGRES_DB:-arc} -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	@$(MAKE) db-migrate

db-shell: ## Open PostgreSQL shell
	$(COMPOSE) exec postgres psql -U $${POSTGRES_USER:-arc} -d $${POSTGRES_DB:-arc}

neo4j-shell: ## Open Neo4j Cypher shell
	$(COMPOSE) exec neo4j cypher-shell -u neo4j -p "$${NEO4J_PASSWORD}"

redis-cli: ## Open Redis CLI
	$(COMPOSE) exec redis redis-cli

# =============================================================================
# Testing
# =============================================================================
.PHONY: test test-api test-webapp lint
test: test-api test-webapp ## Run all tests

test-api: ## Run backend tests
	@echo "$(CYAN)[Arc]$(NC) Running API tests..."
	$(COMPOSE) exec api python -m pytest tests/ -v --tb=short

test-webapp: ## Run frontend tests
	@echo "$(CYAN)[Arc]$(NC) Running webapp tests..."
	$(COMPOSE) exec webapp npm test

lint: ## Run linters on backend
	@echo "$(CYAN)[Arc]$(NC) Running linters..."
	$(COMPOSE) exec api python -m ruff check src/
	$(COMPOSE) exec api python -m mypy src/ --ignore-missing-imports

# =============================================================================
# Cleanup
# =============================================================================
.PHONY: clean clean-volumes clean-all
clean: ## Remove stopped containers and dangling images
	@echo "$(YELLOW)[Arc]$(NC) Cleaning up..."
	$(COMPOSE) down --remove-orphans
	docker image prune -f

clean-volumes: ## Remove all Arc volumes (DESTRUCTIVE)
	@echo "$(RED)[Arc]$(NC) Removing all data volumes..."
	$(COMPOSE) down -v

clean-all: clean-volumes ## Full cleanup: volumes + images
	@echo "$(RED)[Arc]$(NC) Removing all Arc images..."
	docker images --filter "label=com.arc.service" -q | xargs -r docker rmi -f
	docker image prune -f

# =============================================================================
# Health Checks
# =============================================================================
.PHONY: health
health: ## Check health of all services
	@echo "$(CYAN)[Arc]$(NC) Checking service health..."
	@echo ""
	@printf "  %-16s " "API:" && (curl -sf http://localhost:$${API_PORT:-8080}/health > /dev/null 2>&1 && echo "$(GREEN)✓ healthy$(NC)" || echo "$(RED)✗ unreachable$(NC)")
	@printf "  %-16s " "Webapp:" && (curl -sf http://localhost:$${WEBAPP_PORT:-3000} > /dev/null 2>&1 && echo "$(GREEN)✓ healthy$(NC)" || echo "$(RED)✗ unreachable$(NC)")
	@printf "  %-16s " "Neo4j:" && (curl -sf http://localhost:$${NEO4J_HTTP_PORT:-7474} > /dev/null 2>&1 && echo "$(GREEN)✓ healthy$(NC)" || echo "$(RED)✗ unreachable$(NC)")
	@printf "  %-16s " "PostgreSQL:" && ($(COMPOSE) exec -T postgres pg_isready -U $${POSTGRES_USER:-arc} > /dev/null 2>&1 && echo "$(GREEN)✓ healthy$(NC)" || echo "$(RED)✗ unreachable$(NC)")
	@printf "  %-16s " "Qdrant:" && (curl -sf http://localhost:$${QDRANT_HTTP_PORT:-6333}/healthz > /dev/null 2>&1 && echo "$(GREEN)✓ healthy$(NC)" || echo "$(RED)✗ unreachable$(NC)")
	@printf "  %-16s " "Redis:" && ($(COMPOSE) exec -T redis redis-cli ping > /dev/null 2>&1 && echo "$(GREEN)✓ healthy$(NC)" || echo "$(RED)✗ unreachable$(NC)")
	@printf "  %-16s " "Elasticsearch:" && (curl -sf http://localhost:$${ES_PORT:-9200}/_cluster/health > /dev/null 2>&1 && echo "$(GREEN)✓ healthy$(NC)" || echo "$(RED)✗ unreachable$(NC)")
	@echo ""
