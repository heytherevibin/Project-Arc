# Extended Reconnaissance — Implementation Plan

This plan implements extended reconnaissance using the same patterns as the foundation and applying all [lessons learned](./IMPLEMENTATION_ROADMAP.md#lessons-learned-do-not-repeat).

---

## 1. Scope Summary

| Capability            | Tool / approach       | Purpose                          | Pipeline integration      |
|-----------------------|------------------------|----------------------------------|----------------------------|
| URL discovery         | GAU                    | Wayback / URL enumeration        | After crawl or as enrichment |
| Subdomain brute-force | Knockpy                | Active subdomain discovery        | Optional after Subfinder   |
| API discovery         | Kiterunner             | API endpoint discovery            | After HTTP probe           |
| Tech fingerprinting   | Wappalyzer             | Technology detection              | After HTTP probe           |
| WHOIS                 | python-whois           | WHOIS lookups                     | Enrichment                 |
| Passive recon         | Shodan InternetDB      | Passive IP/port/service info      | Enrichment                 |
| Secret hunting        | GitHub (API / dorking) | Repo/secret discovery             | Optional enrichment        |
| Continuous monitoring | New service + scheduler| Re-scan / diff / alerts           | Backend + optional UI      |

---

## 2. Principles (Avoid Past Mistakes)

- **One MCP tool = one port = one `MCP_*_URL`.** No sharing ports; document each in `.env.example`, docker-compose, and README.
- **Structured JSON responses** from every MCP endpoint: `success`, plus tool-specific fields (e.g. `urls`, `technologies`, `whois`).
- **Backend:** New tools extend `BaseTool`; pipeline uses same phase pattern (update phase → run tool → store in Neo4j).
- **UI:** Any new dashboard views use C2 components (`C2Panel`, `C2Table`, `DataReadout`, `CommandBar`); no raw Ant Design cards/tables for primary content. Toasts stay bottom-right above footer; page transitions stay smooth.
- **Neo4j:** All new data is scoped by `project_id`; extend schema and store incrementally as phases complete.
- **Fix causes:** Address config, contract, and layout issues at the source rather than with one-off hacks.

---

## 3. Implementation Order

### 3.1 Foundation (config, ports, docs)

1. **Port allocation (no conflicts with 8000–8005):**
   - GAU: 8006  
   - Knockpy: 8007  
   - Kiterunner: 8008  
   - Wappalyzer: 8009  
   - Whois: 8010  
   - Shodan: 8011  
   - GitHub recon: 8012  

2. **Config and compose**
   - Add to `backend/src/core/config.py`: `MCP_GAU_URL`, `MCP_KNOCKPY_URL`, `MCP_KITERUNNER_URL`, `MCP_WAPPALYZER_URL`, `MCP_WHOIS_URL`, `MCP_SHODAN_URL`, `MCP_GITHUB_RECON_URL` (with sensible defaults pointing at `mcp-recon:8006` … `mcp-recon:8012`).
   - Add to `.env.example`: each `MCP_*_URL` and optional API keys (`SHODAN_API_KEY`, `GITHUB_TOKEN` already present; document that extended recon uses them).
   - In `docker-compose.yml`: add env vars for these URLs on `api`; add ports 8006–8012 on `mcp-recon`; extend healthcheck if needed (e.g. one known-good port).

3. **MCP server entrypoint**
   - In `mcp/servers/main.py`: register new modules (e.g. `servers.gau_server:app` on 8006, etc.) so each tool runs on its assigned port. Follow existing pattern exactly.

4. **README**
   - Update "Reconnaissance Tools" (or equivalent) table with new tools and ports.
   - Keep "If all tools return 404" and "Each tool must use its own port" guidance; add a sentence that extended recon tools use 8006–8012.

### 3.2 MCP servers (one per tool)

Each new server must:

- Expose `GET /` and `GET /health`.
- Expose `POST /tools/<tool_name>` with a Pydantic request body and return structured JSON (`success`, plus tool-specific keys).
- Use the same error-handling and response shape as existing servers (e.g. Subfinder, Naabu).

**Order of implementation:**

1. **GAU server** (`mcp/servers/gau_server.py`, port 8006)  
   - Input: domain or list of domains.  
   - Output: `success`, `urls` (list), optional `count`.  
   - Install/get GAU binary in Dockerfile.recon; document in Dockerfile comments.

2. **Knockpy server** (8007)  
   - Input: domain, optional wordlist.  
   - Output: `success`, `subdomains` (list).  
   - Integrate Knockpy (or equivalent) in Dockerfile.recon.

3. **Kiterunner server** (8008)  
   - Input: base URL(s) or list of URLs.  
   - Output: `success`, `endpoints` or `routes` (list of path/method).  
   - Add Kiterunner to Dockerfile.recon.

4. **Wappalyzer server** (8009)  
   - Input: URL(s).  
   - Output: `success`, `technologies` (list of name/category/version per URL).  
   - Use Wappalyzer (CLI or library) or equivalent; add to Dockerfile.recon.

5. **Whois server** (8010)  
   - Input: domain(s).  
   - Output: `success`, `whois` (dict domain -> text or structured).  
   - Use python-whois in MCP container.

6. **Shodan server** (8011)  
   - Input: IP or domain; use Shodan InternetDB (or Shodan API if key provided).  
   - Output: `success`, `data` (e.g. hostnames, ports, vulns).  
   - Read `SHODAN_API_KEY` from env; document in .env.example.

7. **GitHub recon server** (8012)  
   - Input: org/repo or keywords; optional token.  
   - Output: `success`, `repos` / `findings` (e.g. potential secrets, repo list).  
   - Use `GITHUB_TOKEN`; rate-limit and document in .env.example.

Each server: add to `mcp/servers/main.py` with correct port; extend `mcp/Dockerfile.recon` for any new binaries/deps.

### 3.3 Backend tools and pipeline

1. **Tool classes** (`backend/src/recon/tools/`)
   - Add: `gau.py`, `knockpy.py`, `kiterunner.py`, `wappalyzer.py`, `whois.py`, `shodan.py`, `github_recon.py`.
   - Each extends `BaseTool`, implements `mcp_url` (from settings), `run(target)`, `parse_output(raw)`.
   - Use `call_mcp(tool_name, arguments)` with the same argument names the MCP server expects. Return `ToolResult` with structured data.

2. **Constants**
   - In `backend/src/core/constants.py`: add any new `ScanPhase` or scan types if we introduce distinct phases (e.g. `URL_DISCOVERY`, `TECHNOLOGY_DETECTION`, `WHOIS_ENRICHMENT`, `PASSIVE_ENRICHMENT`). Prefer reusing existing phases (e.g. `ENRICHMENT`) where it fits.

3. **Pipeline integration**
   - In `backend/src/recon/pipeline.py`:
     - **GAU:** Optional phase after Katana (e.g. "URL discovery") or as part of enrichment; feed domains/URLs, store new URLs in Neo4j with `project_id`.
     - **Knockpy:** Optional phase after Subfinder (or parallel); merge subdomains, dedupe, then continue DNS resolution.
     - **Kiterunner:** Optional phase after HTTP probing; run against live URLs; store API endpoints in graph.
     - **Wappalyzer:** Run after HTTP probe or in enrichment; store technologies per URL/host in Neo4j.
     - **Whois:** Enrichment phase; store WHOIS data on Domain node or linked node.
     - **Shodan:** Enrichment; attach passive data to IP/host nodes.
     - **GitHub:** Optional enrichment (e.g. for org/domain); store findings in a way that fits existing schema or a small extension.
   - For each phase: `_update_phase(ScanPhase.XXX, progress)` → run tool → on success store via existing Neo4j helpers (or new ones with `project_id`); on failure append to `_errors` and log. Do not change core pipeline behavior (e.g. Subfinder → dnsx → Naabu → Httpx → Katana → Nuclei) unless we explicitly decide to reorder.

4. **Neo4j schema**
   - Extend `backend/src/graph/schema/` (or equivalent) with any new node/relationship types (e.g. Technology, APIEndpoint, WhoisData) and indexes/constraints; keep `project_id` on all project-scoped data.
   - Add storage methods in pipeline (e.g. `_store_urls_from_gau`, `_store_technologies`, `_store_whois`) that use existing graph client and respect multi-tenancy.

### 3.4 Continuous monitoring

1. **Backend**
   - Add a scheduler (e.g. APScheduler or Celery beat) or a dedicated small service that:
     - Runs on an interval (e.g. daily) or is triggered by API.
     - For each project (or selected projects), re-runs a subset of pipeline (e.g. Subfinder + DNS + diff) or full pipeline.
     - Diffs against previous scan; optionally writes "changes" to Neo4j or a dedicated store.
   - Add API endpoint(s): e.g. "list monitoring jobs", "trigger re-scan for project", "get last diff".
   - Config: enable/disable monitoring, interval, and which phases to run (env or DB).

2. **UI (optional for extended recon)**
   - If time permits: dashboard view for "Monitoring" using C2 components: C2Panel, C2Table for jobs/last run/diff summary; toasts bottom-right; no new Ant Design–only screens.
   - Otherwise: defer to a follow-up; API is enough for extended recon.

### 3.5 UI and reporting

- **Existing scan/results views:** When pipeline returns new data (URLs, technologies, WHOIS, etc.), expose them in existing scan results modal (e.g. extra tabs or sections) using C2Panel + C2Table; keep full text visible, no ellipsis; responsive scroll.
- **Reports:** Extend report export (JSON/PDF) to include new data (technologies, WHOIS, Shodan, etc.) using the same report export module and types.
- **Settings:** If we add new API keys (e.g. Shodan, GitHub), show them in Settings in the same C2 two-column layout; reuse existing pattern for "Check MCP" (e.g. "Check Shodan" if applicable).

---

## 4. Testing and quality

- **Backend:** Unit tests for each new tool class (mock MCP response; assert `ToolResult` and parse_output). Integration test for pipeline with one new phase (e.g. GAU or Whois) and mocked Neo4j if needed.
- **MCP:** Manual or scripted curl to `POST /tools/<name>` and `GET /health` for each new server; verify JSON shape.
- **Docs:** After each tool, update README table and .env.example. Keep IMPLEMENTATION_ROADMAP.md and this file in sync when we add or drop an extended recon item.

---

## 5. Checklist Before Calling Extended Recon Done

- [ ] All new MCP_*_URL and MCP_*_PORT in config, .env.example, docker-compose.
- [ ] Each new tool: MCP server (/, /health, POST /tools/xxx), backend Tool class, pipeline phase or enrichment step, Neo4j storage with project_id.
- [ ] No new UI that breaks C2 design system or toast/footer/transition rules.
- [ ] README and IMPLEMENTATION_ROADMAP.md updated; "lessons" still respected.
- [ ] Continuous monitoring: at least backend scheduler + API; UI optional.
- [ ] Report export includes new data where relevant.
- [ ] All lessons (one port per tool, structured JSON, C2 UI, root-cause fixes) applied.

---

## 6. References

- [IMPLEMENTATION_ROADMAP.md](./IMPLEMENTATION_ROADMAP.md) — Foundation summary and lessons  
- [../backend/src/recon/pipeline.py](../backend/src/recon/pipeline.py) — Pipeline structure  
- [../backend/src/recon/tools/base.py](../backend/src/recon/tools/base.py) — BaseTool contract  
- [../mcp/servers/main.py](../mcp/servers/main.py) — MCP server registration  
- [../.env.example](../.env.example) — Env and API keys
