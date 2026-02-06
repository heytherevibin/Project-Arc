# Arc - Enterprise Autonomous AI Red Team Framework

Arc is an enterprise-grade autonomous AI-powered penetration testing and red team framework. It automates reconnaissance, vulnerability discovery, and attack surface mapping using a sophisticated pipeline of security tools orchestrated through MCP (Model Context Protocol).

## Features

- **Automated Reconnaissance Pipeline**: Subdomain enumeration, DNS resolution, port scanning, HTTP probing, web crawling, and vulnerability scanning
- **Neo4j Attack Surface Graph**: All discovered assets are stored in a graph database for relationship analysis
- **Interactive Graph Visualization**: Visual exploration of attack surface with force-directed graph rendering
- **Real-time Updates**: WebSocket-based live updates for scan progress and findings
- **Enterprise UI**: Dark minimal Mission Control dashboard built with Next.js and Ant Design
- **Project & Scan Reports**: Comprehensive reporting with vulnerability summaries and risk scores
- **MCP Tool Integration**: Security tools exposed via FastMCP servers
- **ELK Stack Logging**: Structured logging with Elasticsearch, Logstash, and Kibana
- **JWT Authentication**: Secure API access with token-based authentication

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Mission Control (Next.js)                   │
│                     Port 3000                                   │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
┌─────────────────────────────────┼───────────────────────────────┐
│                     API Gateway (FastAPI)                       │
│                     Port 8080                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐         │
│  │   REST   │  │WebSocket │  │   Auth   │  │  Health  │         │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘         │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
┌───────┴───────┐         ┌───────┴───────┐         ┌───────┴───────┐
│    Neo4j      │         │     Redis     │         │ Elasticsearch │
│   Port 7687   │         │   Port 6379   │         │   Port 9200   │
└───────────────┘         └───────────────┘         └───────────────┘
                                  │
┌─────────────────────────────────┼───────────────────────────────┐
│                     MCP Recon Server (Kali)                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐         │
│  │  Naabu   │  │  Httpx   │  │Subfinder │  │  Nuclei  │         │
│  │  :8000   │  │  :8001   │  │  :8002   │  │  :8005   │         │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘         │
│  ┌──────────┐  ┌──────────┐                                     │
│  │   dnsx   │  │  Katana  │                                     │
│  │  :8003   │  │  :8004   │                                     │
│  └──────────┘  └──────────┘                                     │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- At least 8GB RAM
- Ports 3000, 8080, 7474, 7687, 6379, 9200, 5601 available

### 1. Clone and Configure

```bash
# Copy environment template
cp .env.example .env

# Edit .env and set required values:
# - JWT_SECRET_KEY (generate with: openssl rand -hex 32)
# - NEO4J_PASSWORD
# - OPENAI_API_KEY or ANTHROPIC_API_KEY (for AI agent features)
```

### 2. Start Services

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f

# Check health
curl http://localhost:8080/health
```

**Full clean rebuild** (no cache; use if images or config are stale):

```bash
./scripts/rebuild.sh
# Or: docker compose down && docker compose build --no-cache && docker compose up -d
```

**If Neo4j fails to start** (`container arc-neo4j is unhealthy`):

1. Set a non-empty `NEO4J_PASSWORD` in `.env` (required).
2. Inspect logs: `docker compose logs neo4j`.
3. If the container exits immediately, try a clean Neo4j volume:  
   `docker compose down && docker volume rm arc-neo4j-data arc-neo4j-logs 2>/dev/null; docker compose up -d`  
   (This wipes Neo4j data; only do this for a fresh start.)

**Data persistence and scalability**

- **Neo4j**, **Redis**, and **Elasticsearch** use Docker named volumes (`neo4j-data`, `neo4j-logs`, `redis-data`, `elasticsearch-data`), so data survives container restarts and `docker compose down`.
- Projects, users, targets, scans, and the attack graph are stored in Neo4j; the API is the only writer, so the graph stays consistent.
- For production scale you can: run Neo4j Causal Cluster or Aura, use Redis Cluster, add Elasticsearch nodes, and put the API behind a load balancer with sticky sessions if you rely on WebSockets.

### 3. Access Mission Control

Open http://localhost:3000 in your browser.

Default ports:
- Mission Control: http://localhost:3000
- API: http://localhost:8080
- Neo4j Browser: http://localhost:7474
- Kibana: http://localhost:5601

**Getting real scan results**

Scans run the real reconnaissance pipeline (Subfinder, dnsx, Naabu, Httpx, Katana, Nuclei). If scans complete but **Scan Results** show all zeros (0 subdomains, 0 ports, 0 vulnerabilities), the tools are not returning data. Common causes:

1. **MCP recon server not running or unreachable** – The backend calls MCP tool URLs (e.g. `MCP_SUBFINDER_URL`, `MCP_NUCLEI_URL`) from `.env`. If those services are down or wrong, each phase fails and the pipeline continues with empty data. Start the MCP recon stack (see `mcp/`) and set the `MCP_*_URL` variables so the API can reach them.
2. **All tools return 404** – Usually every `MCP_*_URL` points to the same host:port (e.g. all to the API or all to port 8000). Each tool must use its **own port**: Naabu=8000, Httpx=8001, Subfinder=8002, dnsx=8003, Katana=8004, Nuclei=8005. In `.env` set each URL separately (e.g. `MCP_SUBFINDER_URL=http://mcp-recon:8002`). Run **Settings → Check MCP URLs** in the UI; if any show "Wrong server" or "404", fix that URL and restart API and `mcp-recon`.
3. **Tool binaries not installed (fallback)** – When MCP fails, the backend falls back to running tools as subprocesses (e.g. `subfinder`, `naabu`, `nuclei`). If those binaries are not on the `PATH` of the container/host running the API, you get "Tool not found" and empty results.
4. **Check backend logs** – Look for messages like `Subdomain enumeration failed`, `MCP connection failed`, `Tool not found`, or phase-specific errors. They indicate which tool or connection is failing.
5. **Naabu/port scan failed (e.g. "rosetta error" on Apple Silicon)** – The MCP image builds for the host architecture (amd64 or arm64). On Apple Silicon, rebuild so native ARM64 binaries are used: `docker compose build mcp-recon && docker compose up -d mcp-recon`. No need for `--platform linux/amd64`.

After fixing MCP or installing tools, run a scan again (e.g. target `scanme.nmap.org` or `testphp.vulnweb.com`); results should then appear in Scan Results and in Targets/Vulnerabilities.

## Project Structure

```
arc/
├── docs/                    # Implementation plans (IMPLEMENTATION_ROADMAP.md, EXTENDED_RECON_IMPLEMENTATION.md)
├── backend/                 # Python FastAPI backend
│   ├── src/
│   │   ├── api/            # REST & WebSocket endpoints
│   │   ├── core/           # Config, logging, exceptions
│   │   ├── graph/          # Neo4j client and models
│   │   └── recon/          # Reconnaissance pipeline
│   ├── Dockerfile
│   └── requirements.txt
├── webapp/                  # Next.js frontend
│   ├── src/
│   │   ├── app/            # Next.js app router pages
│   │   ├── components/     # Reusable components
│   │   ├── hooks/          # Custom React hooks
│   │   ├── lib/            # Utilities and API client
│   │   ├── store/          # Zustand state management
│   │   └── types/          # TypeScript definitions
│   ├── Dockerfile
│   └── package.json
├── mcp/                     # MCP tool servers
│   ├── servers/            # FastMCP server implementations
│   ├── Dockerfile.recon
│   └── requirements.txt
├── infrastructure/          # Infrastructure configs
│   └── logstash/           # ELK pipeline configuration
├── docker-compose.yml       # Production Docker Compose
├── pyproject.toml          # Python project config
└── .env.example            # Environment template
```

## Development

### Backend Development

```bash
cd backend

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt

# Run development server
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8080
```

### Frontend Development

```bash
cd webapp

# Install dependencies
npm install

# Run development server
npm run dev
```

**If you see** `npm warn Unknown env config "devdir"`: some environments (e.g. Cursor IDE) set `NPM_CONFIG_DEVDIR`, which npm does not recognize. Use the project’s npm wrapper so npm runs without that variable (recommended, stable workaround):

- **macOS/Linux:** `./npmw install`, `./npmw run dev`, `./npmw run type-check`, etc.
- **Windows (cmd):** `npmw.cmd run dev`, `npmw.cmd run type-check`, etc.
- **Windows (PowerShell / any):** `node scripts/run-npm-without-devdir.js run dev`

After `npm install`, if the variable is set, a one-line tip will remind you to use `./npmw` for future commands.

### Running Tests

```bash
# Backend tests (requires venv with dependencies: pip install -r requirements.txt)
cd backend
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pytest

# Verify extended recon backend imports (same venv)
cd backend && PYTHONPATH=src python scripts/verify_recon_extensions.py

# Frontend tests
cd webapp
npm test
```

## API Documentation

When running in development mode, API documentation is available at:
- Swagger UI: http://localhost:8080/docs
- ReDoc: http://localhost:8080/redoc

## Security Considerations

- All graph queries are filtered by `project_id` for multi-tenant isolation
- JWT tokens with short expiration for access and longer for refresh
- Passwords hashed with bcrypt
- Network isolation between Docker services
- No sensitive data logged
- Rate limiting on API endpoints

## Reconnaissance Tools

Core recon tools use ports 8000–8005; extended recon tools use 8006–8012. Each tool has its own port and `MCP_*_URL` in `.env`.

| Tool | Port | Description |
|------|------|-------------|
| Naabu | 8000 | Fast port scanning |
| Httpx | 8001 | HTTP probing and tech detection |
| Subfinder | 8002 | Passive subdomain discovery |
| dnsx | 8003 | DNS resolution |
| Katana | 8004 | Web crawling |
| Nuclei | 8005 | Vulnerability scanning |
| GAU | 8006 | Wayback / URL discovery |
| Knockpy | 8007 | Active subdomain brute-force |
| Kiterunner | 8008 | API endpoint discovery |
| Wappalyzer | 8009 | Technology fingerprinting |
| Whois | 8010 | WHOIS lookups |
| Shodan | 8011 | Passive recon / InternetDB |
| GitHub recon | 8012 | Repo / secret discovery |

## Continuous Monitoring

When you run the stack with **Docker Compose**, the backend (API + monitoring scheduler) runs **inside the `api` container**. Dependencies are installed in the image; no manual `pip install` is needed. The scheduler starts automatically when the API starts.

Use the Monitoring API (requires auth; base URL is your API, e.g. `http://localhost:8080` when using default ports):

- **GET** `/api/v1/monitoring/jobs?project_id=...` — list monitoring jobs (optionally filtered by project)
- **POST** `/api/v1/monitoring/jobs?project_id=...` — create a job (body: `{ "target": "example.com", "interval_hours": 24 }`)
- **POST** `/api/v1/monitoring/trigger?project_id=...` — trigger a re-scan now (body: `{ "target": "example.com" }`)
- **DELETE** `/api/v1/monitoring/jobs/{job_id}` — remove a job

Example with Docker (API on port 8080, replace `<project_id>` and use a valid JWT):

```bash
# Create a monitoring job (re-scan example.com every 24 hours)
curl -X POST "http://localhost:8080/api/v1/monitoring/jobs?project_id=<project_id>" \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"target": "example.com", "interval_hours": 24}'

# Trigger a re-scan now
curl -X POST "http://localhost:8080/api/v1/monitoring/trigger?project_id=<project_id>" \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

Jobs are stored in memory (in the API container); the scheduler runs every 5 minutes and starts a full recon scan for any job whose interval has elapsed. Set `MONITORING_ENABLED=false` in `.env` to disable the scheduler.

## Pipeline extended tools

During a **full recon** scan, the pipeline runs optional enrichment tools (Whois, GAU, Wappalyzer, Shodan, Knockpy, Kiterunner, GitHub recon). You can choose which of these run:

- **Settings UI:** Dashboard → Settings → **Pipeline extended tools**. Check or uncheck each tool and click **Save pipeline tools**. Only tools that are enabled here and have an MCP URL configured will run.
- **API:** **GET** `/api/v1/settings/pipeline-tools` returns the current list; **PUT** `/api/v1/settings/pipeline-tools` with body `{ "tools": ["whois", "gau", "wappalyzer", "shodan", "knockpy", "kiterunner", "github_recon"] }` updates it (auth required). Stored in Neo4j; overrides the default from `PIPELINE_EXTENDED_TOOLS` in `.env`.

Default (if not set in Settings): `whois,gau,wappalyzer,shodan`. Add `knockpy`, `kiterunner`, or `github_recon` in Settings to include them in the pipeline.

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| JWT_SECRET_KEY | Secret for JWT signing (min 32 chars) | Yes |
| NEO4J_PASSWORD | Neo4j database password | Yes |
| MONITORING_ENABLED | Enable continuous monitoring scheduler (default: true) | No |
| MONITORING_DEFAULT_INTERVAL_HOURS | Default re-scan interval in hours (1–168, default: 24) | No |
| PIPELINE_EXTENDED_TOOLS | Comma-separated tools to run in pipeline (default: whois,gau,wappalyzer,shodan; overridable in Settings UI) | No |
| OPENAI_API_KEY | OpenAI API key for AI features | No |
| ANTHROPIC_API_KEY | Anthropic API key for AI features | No |
| LLM_PROVIDER | Primary LLM provider (openai/anthropic) | No |

## License

MIT License

## Contributing

Contributions are welcome. Please read the contributing guidelines before submitting a pull request.
