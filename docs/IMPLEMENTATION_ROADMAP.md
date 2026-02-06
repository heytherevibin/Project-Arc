# Arc Implementation Roadmap

This document summarizes the foundation (complete), extended reconnaissance scope, and **lessons learned** so the same mistakes are not repeated.

---

## Foundation: Reconnaissance — **Complete**

**Technical stack:** Python 3.11, Node.js 22 LTS, Docker Compose, Neo4j, Redis, ELK, FastAPI + WebSocket, Next.js + Ant Design (C2-style UI), JWT, pytest + Vitest.

**Deliverables (done):**

1. Enterprise directory structure  
2. Docker infrastructure (Neo4j, Redis, ELK, Kali-based MCP recon)  
3. Core Python package (config, logging, exceptions, constants)  
4. Neo4j graph schema with attack surface model  
5. MCP servers: Naabu, Httpx, Subfinder, dnsx, Katana, Nuclei (one port per tool: 8000–8005)  
6. Recon pipeline orchestrator (subdomain → DNS → port → HTTP → crawl → vuln)  
7. FastAPI backend with REST + WebSocket  
8. Mission Control UI (C2 design system, dark minimal)  
9. Real-time scan monitoring  
10. Basic reporting (JSON/PDF export)

---

## Extended Reconnaissance

**Scope (from plan):**

- **GAU** — Wayback Machine / URL discovery  
- **Knockpy** — Active subdomain brute-force  
- **Kiterunner** — API endpoint discovery  
- **Wappalyzer** — Technology fingerprinting  
- **python-whois** — WHOIS lookups  
- **Shodan InternetDB** — Passive recon  
- **GitHub secret hunting**  
- **Continuous monitoring**

See [EXTENDED_RECON_IMPLEMENTATION.md](./EXTENDED_RECON_IMPLEMENTATION.md) for the implementation plan.

---

## Lessons Learned (Do Not Repeat)

### 1. UI & design system

- **Use the C2 design system consistently.** Prefer `C2Panel`, `DataReadout`, `C2Table`, `CommandBar`, `IndicatorLight`, `StatusStrip`, `DashboardFooter` — do not revert to raw Ant Design `Card`/`Statistic`/`Table` for new pages.
- **Typography:** Orbitron (headings), JetBrains Mono (body). Apply via `globals.css` and theme; keep monospace dominant.
- **Theme:** Red/black mission-control palette; primary accent `#cc3333`; no ad-hoc colors.
- **Tables:** Do **not** use `ellipsis: true` on columns. Use proper column widths, `scroll={{ x: ... }}`, and CSS so full text is visible (word-wrap, overflow-wrap). Wrap tables in a responsive container.
- **Empty states:** Always wrap in a `C2Panel` with a clear title (e.g. "DASHBOARD", "VULNERABILITIES") so layout and branding stay consistent.
- **Modals:** Use `.ant-modal-header` + `.ant-modal-close` alignment (flex, vertical center). Command bar titles: `margin: 0`, `line-height: 32px`, aligned with buttons.
- **Toasts:** Position bottom-right, **above** the fixed footer (`bottom: 88px` or equivalent). Use smooth enter/leave (e.g. `cubic-bezier`, `translate3d`, `will-change`). Do not use top-center.
- **Page transitions:** Use a single wrapper (e.g. `PageTransition`) with `key={pathname}`, `contain: layout style`, `transform: translateZ(0)`, and a short fade (e.g. 0.25s) so route changes (including login/signup ↔ dashboard) feel smooth.
- **Form errors:** Reserve space below inputs (e.g. `margin-top` on `.ant-form-item-explain`) so validation messages don't shift layout.
- **Selects/inputs:** Ensure selected text and placeholders are fully visible (no truncation); use global CSS for `.ant-select-selection-item` / `.ant-select-selection-placeholder` as needed.

### 2. MCP & backend

- **One tool, one port, one URL.** Each MCP tool must have its own port and `MCP_*_URL` in `.env`. Never point multiple tools at the same host:port; 404s and "Wrong server" usually mean shared or wrong URL.
- **API contract:** MCP endpoints must accept POST and return **structured JSON** with at least `success` and tool-specific fields (e.g. `subdomains`, `ports`, `resolved`). The backend expects this shape; avoid returning only a raw string without a wrapper.
- **Health & discovery:** Each server exposes `GET /` and `GET /health`. Document the correct `POST /tools/<tool_name>` path. If scans get 404, check that the URL is the tool's base (no extra path) and that the container was rebuilt after adding routes.
- **Config:** Add every new `MCP_*_URL` and `MCP_*_PORT` to `.env.example`, `docker-compose.yml` (api env + mcp-recon ports), and backend config. Document in README how to fix "all tools return 404".
- **Backend tools:** New tools extend `BaseTool`, implement `mcp_url`, `run()`, and `parse_output()`. Use `call_mcp()` with the same argument shape the MCP server expects. Pipeline phases should use the same pattern: get settings → run tool → handle success/failure → store in Neo4j.

### 3. Neo4j & data

- **Multi-tenant:** All graph reads/writes are scoped by `project_id`. New node types and relationships must be included in schema and queries with `project_id` (or equivalent) so isolation is never broken.
- **Pipeline storage:** Store results as each phase completes (subdomains, DNS, ports, URLs, vulnerabilities). Do not buffer everything to the end; the UI and reports depend on incremental updates.

### 4. Frontend tooling

- **NPM:** If the environment sets `NPM_CONFIG_DEVDIR`, use the project's npm wrapper (`./npmw`, `npmw.cmd`, or `node scripts/run-npm-without-devdir.js`) to avoid "Unknown env config devdir" warnings. Document this in README and keep the postinstall tip.

### 5. Reporting & types

- **Report export:** Use existing `reportExport.ts` (e.g. jsPDF + autoTable). For type assertions (e.g. `lastAutoTable.finalY`), use a narrow, explicit type (e.g. `doc as jsPDF & { lastAutoTable?: { finalY: number } }`) instead of `(doc as any)`.

### 6. General

- **Fix root cause, not symptoms.** When something is wrong (e.g. truncation, alignment, 404s), fix the layout/contract/config that causes it rather than one-off overrides in a single component.
- **Consistency:** New dashboard pages should follow the same layout: CommandBar (title + actions), C2Panel, C2Table or DataReadout where appropriate. Reuse existing patterns from dashboard, scans, vulnerabilities, reports, and settings.

---

## References

- Master plan: `.cursor/plans/arc_pentesting_framework_2d478447.plan.md`  
- Extended recon implementation: [docs/EXTENDED_RECON_IMPLEMENTATION.md](./EXTENDED_RECON_IMPLEMENTATION.md)  
- README: [../README.md](../README.md)
