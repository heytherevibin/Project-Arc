# Project Arc

**Enterprise autonomous AI red team and penetration testing framework.** Arc automates reconnaissance, vulnerability discovery, attack surface mapping, and reporting through a mission-control dashboard, a modular recon pipeline backed by MCP (Model Context Protocol) tool servers, and a Neo4j-powered graph of assets and findings.

---

## Overview

Arc provides:

- **Mission Control UI** — Next.js dashboard (Project ARC) with dark, mission-control styling: projects, targets, scans, vulnerabilities, attack surface graph (2D/3D), attack paths, identity graph, missions, approvals, chat, settings, and real-time WebSocket status.
- **Reconnaissance pipeline** — Orchestrated subdomain enumeration (Subfinder, optional Knockpy), DNS resolution (dnsx), port scanning (Naabu), HTTP probing (Httpx), web crawling (Katana), vulnerability scanning (Nuclei), plus optional enrichment (Whois, GAU, Wappalyzer, Shodan, Kiterunner, GitHub recon). Pipeline is split into **orchestrators** (tool runners returning normalized data) and pipeline (Neo4j storage and phase progress).
- **Neo4j attack surface graph** — Domains, subdomains, IPs, ports, URLs, technologies, vulnerabilities, WHOIS, Shodan, API endpoints, GitHub repos/findings. Schema includes core attack surface, identity (AD/Azure), attack graph, and MITRE ATT&CK; indexes live in `indexes.cypher`.
- **Backend API** — FastAPI: auth (JWT), projects, targets, scans, vulnerabilities, **findings** (CRUD for manual findings), reports, graph data/stats/attack paths, recon tools health, monitoring jobs, settings (pipeline tool toggles), missions, agents; WebSocket for real-time updates (handler/events/streams); optional GraphQL.
- **AI and agents** — LangGraph workflow (supervisor + specialists: recon, vuln analysis, exploit, post-exploit, lateral, report) with approval gates; cognitive memory (episodic, semantic, procedural, working); intelligence (MITRE mapping, pathfinding, scoring, planner); optional Sliver C2 gRPC client (`backend/src/c2/`).
- **Reporting** — Executive summary, technical report, remediation, compliance; Markdown templates (executive_summary.md, technical_report.md, remediation.md) and template loader; PDF and SARIF exporters.
- **Infrastructure** — Docker Compose: API, webapp, Neo4j (with GDS/APOC), PostgreSQL, Redis, Qdrant, Elasticsearch, Kibana, Logstash, MCP recon container (multi-port tool servers). Optional lab compose for vulnerable targets (DVWA, Juice Shop, WebGoat).

All configuration is via environment variables; no hardcoded secrets or URLs in code.

---

## Features

| Area | Capabilities |
|------|----------------|
| **Recon** | Subdomain enum (Subfinder, Knockpy), DNS (dnsx), port scan (Naabu), HTTP probe (Httpx), crawl (Katana), vuln scan (Nuclei), passive DNS (CT), Whois, GAU, Wappalyzer, Shodan, Kiterunner, GitHub recon |
| **Data** | Neo4j (graph), PostgreSQL (episodic/missions), Redis (cache), Qdrant (vector), Elasticsearch (logs) |
| **UI** | Projects, targets, scans with result tabs (subdomains, IPs, ports, URLs, tech, WHOIS, Shodan, API endpoints, GitHub), vulnerabilities, manual findings, reports, 2D/3D attack graph, attack paths, identity graph, missions, approvals, agent chat, settings, MCP health |
| **API** | REST (`/api/v1/...`): auth, projects, targets, scans, vulnerabilities, findings, reports, graph, tools, monitoring, settings, missions, agents; WebSocket `/ws`; optional GraphQL |
| **Automation** | Continuous monitoring (scheduler + jobs/trigger API), configurable pipeline tool set per Settings |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  Mission Control (Next.js)                       │
│                  Port 3000                                      │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
┌─────────────────────────────────┼───────────────────────────────┐
│                  API (FastAPI) · Port 8080                      │
│  REST · WebSocket · Auth · Graph · Reports · Findings · Agents  │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
    ┌─────────────┬───────────────┼───────────────┬─────────────┐
    │             │               │               │             │
┌───┴───┐   ┌─────┴─────┐   ┌─────┴─────┐   ┌─────┴─────┐   ┌────┴────┐
│ Neo4j │   │ Postgres  │   │  Redis   │   │ Qdrant   │   │  ELK   │
│ 7687  │   │  5432     │   │  6379    │   │  6333    │   │ 9200   │
└───────┘   └───────────┘   └──────────┘   └──────────┘   └────────┘
    │
    │  MCP tool servers (mcp-recon container; one port per tool)
┌───┴───────────────────────────────────────────────────────────────┐
│ Naabu · Httpx · Subfinder · dnsx · Katana · Nuclei · GAU · ...   │
│ 8000   8001    8002       8003  8004     8005      8006           │
└───────────────────────────────────────────────────────────────────┘
```

---

## Project structure

```
arc/
├── backend/                    # Python FastAPI backend
│   ├── src/
│   │   ├── api/               # REST, WebSocket, GraphQL, middleware
│   │   │   ├── routes/        # auth, projects, targets, scans, vulnerabilities,
│   │   │   │                  # findings, reports, graph, monitoring, settings,
│   │   │   │                  # missions, agents, websocket
│   │   │   └── websocket/     # handler, events, streams
│   │   ├── agents/            # LangGraph supervisor + specialists, workflow, supervisor_graph
│   │   ├── c2/                # Sliver gRPC client (optional)
│   │   ├── core/              # Config, logging, exceptions, constants
│   │   ├── graph/             # Neo4j client, schema (cypher), indexes, queries, projections
│   │   ├── intelligence/     # MITRE, pathfinding, scoring, planner (AGE, CALDERA)
│   │   ├── memory/           # Episodic, semantic, procedural, working memory
│   │   ├── recon/            # Pipeline + orchestrators + tools
│   │   │   ├── orchestrators/ # passive_dns, subdomain_enum, port_scan, http_probe,
│   │   │   │                  # web_crawl, shodan, github, whois, gau, wappalyzer,
│   │   │   │                  # knockpy, kiterunner
│   │   │   ├── tools/        # MCP-backed tools (Subfinder, dnsx, Naabu, etc.)
│   │   │   ├── passive/      # Cert transparency, OSINT
│   │   │   ├── continuous/   # Monitor, alerting, diff
│   │   │   └── stealth/      # Rate limit, Tor wrapper
│   │   └── reporting/        # Generators, exporters, Markdown templates + loader
│   ├── tests/
│   ├── Dockerfile
│   └── requirements.txt
├── webapp/                     # Next.js Mission Control
│   ├── src/app/               # Login, register, dashboard (overview, projects, targets,
│   │   │                       # scans, vulnerabilities, graph, attack-paths, identity,
│   │   │                       # missions, approvals, chat, timeline, settings)
│   │   ├── components/        # C2 panels, graph, chat, approval, dashboard
│   │   ├── hooks/             # useWebSocket
│   │   ├── lib/               # api, theme, neo4j helpers, d3-force-3d, reportExport
│   │   └── store/             # Zustand (auth, app)
│   ├── Dockerfile
│   └── package.json
├── mcp/                        # MCP tool servers (single image, multiple ports)
│   ├── servers/               # Naabu, Httpx, Subfinder, dnsx, Katana, Nuclei, GAU,
│   │   │                       # Knockpy, Kiterunner, Wappalyzer, Whois, Shodan,
│   │   │                       # GitHub recon, GVM, Nikto, Commix, Sliver, Havoc,
│   │   │                       # BloodHound, Certipy, Impacket, CrackMapExec, etc.
│   ├── Dockerfile.recon
│   └── requirements.txt
├── infrastructure/             # Logstash pipeline (ELK)
├── lab/                       # Optional vulnerable targets (README, docker-compose.lab)
├── docs/                      # Implementation roadmap, status, extended recon
├── scripts/                   # rebuild.sh
├── docker-compose.yml         # API, webapp, Neo4j, Postgres, Redis, Qdrant, ELK, mcp-recon
├── docker-compose.dev.yml     # Dev overrides
├── docker-compose.lab.yml     # DVWA, Juice Shop, WebGoat
├── Makefile                   # build, up, down, dev, lab, test, health, db-*
└── .env.example               # Environment template
```

---

## Quick start

### Prerequisites

- Docker and Docker Compose
- 8GB+ RAM recommended
- Ports 3000, 8080, 5432, 6333, 6379, 7474, 7687, 9200, 5601 (and MCP ports if exposed) free

### 1. Clone and configure

```bash
git clone https://github.com/heytherevibin/Project-Arc.git arc && cd arc
cp .env.example .env
```

Edit `.env` and set at least:

- `JWT_SECRET_KEY` — e.g. `openssl rand -hex 32`
- `NEO4J_PASSWORD` — Neo4j auth
- `CORS_ORIGINS` — e.g. `http://localhost:3000,http://127.0.0.1:3000`

Optional: LLM keys (OpenAI/Anthropic) for agents; MCP URLs default to `http://mcp-recon:8000` etc. for Docker.

### 2. Start stack

```bash
docker compose up -d
# Or: make up
```

Wait for health (e.g. `make health` or `curl -s http://localhost:8080/health`). Then open:

- **Mission Control:** http://localhost:3000  
- **API docs:** http://localhost:8080/docs  
- **Neo4j Browser:** http://localhost:7474 (user `neo4j`, password from `NEO4J_PASSWORD`)

### 3. First use

1. Register a user at http://localhost:3000/register  
2. Create a project, add a target (e.g. domain or `scanme.nmap.org`)  
3. Run a scan; view results in Scan Results (subdomains, IPs, ports, URLs, vulns, etc.) and in Targets / Vulnerabilities  
4. Use **Settings → Check MCP URLs** to verify tool endpoints; enable/disable pipeline tools (Whois, GAU, Shodan, Knockpy, Kiterunner, GitHub recon, etc.)

**Full rebuild (no cache):**

```bash
./scripts/rebuild.sh
# Or: docker compose down && docker compose build --no-cache && docker compose up -d
```

**If scans show zeros:** Ensure MCP recon is running and each tool has its own port (see [Reconnaissance tools](#reconnaissance-tools)). Set `MCP_*_URL` in `.env` so the API can reach `mcp-recon` (e.g. `http://mcp-recon:8002` for Subfinder). Use Settings → Check MCP URLs in the UI.

---

## Development

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
# Run API (from repo root so PYTHONPATH can resolve)
PYTHONPATH=src uvicorn api.main:app --reload --host 0.0.0.0 --port 8080
```

### Frontend

```bash
cd webapp
npm install
npm run dev
```

If you see npm warnings about `NPM_CONFIG_DEVDIR`, use the project wrapper: `./npmw run dev` (or `npmw.cmd` on Windows).

### Tests

```bash
# Backend (from backend with venv active)
cd backend && pytest

# Or via Docker
make test-api

# Frontend
cd webapp && npm test
# Or: make test-webapp
```

---

## API overview

| Prefix | Description |
|--------|-------------|
| `/api/v1/auth` | Login, register, refresh |
| `/api/v1/projects` | Projects CRUD |
| `/api/v1/targets` | Targets per project |
| `/api/v1/scans` | Create scan, list, get results |
| `/api/v1/vulnerabilities` | List/filter vulns, summary |
| `/api/v1/findings` | Manual findings CRUD |
| `/api/v1/reports` | Generate/export reports |
| `/api/v1/graph` | Graph data, stats, attack paths |
| `/api/v1/tools` | Recon tool health (MCP) |
| `/api/v1/monitoring` | Jobs, trigger re-scan |
| `/api/v1/settings` | Pipeline tools, etc. |
| `/api/v1/missions` | Missions |
| `/api/v1/agents` | Agent chat and tools |
| `/ws` | WebSocket (query param `token`) |

---

## Reconnaissance tools

Core and extended tools each use a dedicated port and `MCP_*_URL` in `.env`. Default host in Docker is `mcp-recon`.

| Tool | Port | Description |
|------|------|-------------|
| Naabu | 8000 | Port scanning |
| Httpx | 8001 | HTTP probing |
| Subfinder | 8002 | Subdomain discovery |
| dnsx | 8003 | DNS resolution |
| Katana | 8004 | Web crawling |
| Nuclei | 8005 | Vulnerability scanning |
| GAU | 8006 | URL discovery (Wayback, etc.) |
| Knockpy | 8007 | Subdomain brute-force |
| Kiterunner | 8008 | API endpoint discovery |
| Wappalyzer | 8009 | Technology fingerprinting |
| Whois | 8010 | WHOIS lookups |
| Shodan | 8011 | Passive recon / InternetDB |
| GitHub recon | 8012 | Repos and code search |

Additional MCP servers (GVM, Nikto, Commix, Sliver, Havoc, BloodHound, Certipy, Impacket, CrackMapExec, etc.) use further ports; see `.env.example` and `mcp/servers/`.

Pipeline tool selection is configurable in **Settings → Pipeline extended tools** (stored in Neo4j; overrides `PIPELINE_EXTENDED_TOOLS` in `.env`).

---

## Monitoring

The API runs an internal scheduler when `MONITORING_ENABLED=true`. Authenticated endpoints:

- **POST** `/api/v1/monitoring/jobs?project_id=...` — create job: `{ "target": "example.com", "interval_hours": 24 }`
- **GET** `/api/v1/monitoring/jobs?project_id=...` — list jobs
- **POST** `/api/v1/monitoring/trigger?project_id=...` — trigger re-scan: `{ "target": "example.com" }`
- **DELETE** `/api/v1/monitoring/jobs/{job_id}` — delete job

---

## Lab environment

Optional vulnerable apps for testing (do not expose to the internet):

```bash
make lab
# Or: docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d
```

Targets: DVWA (8880), Juice Shop (8881), WebGoat (8882). See `lab/README.md`.

---

## Environment variables (main)

| Variable | Description | Required |
|----------|-------------|----------|
| `JWT_SECRET_KEY` | JWT signing secret (min 32 chars) | Yes |
| `NEO4J_PASSWORD` | Neo4j password | Yes |
| `CORS_ORIGINS` | Comma-separated origins (e.g. http://localhost:3000) | Yes for browser |
| `POSTGRES_PASSWORD` | PostgreSQL password | Yes for API |
| `MCP_*_URL` | Per-tool MCP base URLs | For real scan results |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | LLM for agents | Optional |
| `MONITORING_ENABLED` | Enable monitoring scheduler (default: true) | No |
| `PIPELINE_EXTENDED_TOOLS` | Default pipeline tools (overridable in Settings) | No |

See `.env.example` for the full list.

---

## Security

- Multi-tenant isolation: graph and API filter by `project_id`.
- JWT access and refresh tokens; bcrypt password hashing (72-byte limit handled).
- No sensitive values in logs; rate limiting on API (WebSocket upgrade excluded).
- CORS and env-based configuration; no hardcoded secrets.

---

## License

MIT License.

---

## Contributing

Contributions are welcome. Open an issue or pull request on [GitHub](https://github.com/heytherevibin/Project-Arc).
