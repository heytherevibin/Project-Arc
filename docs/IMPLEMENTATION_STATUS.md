# Arc Implementation Status (vs Plan)

Status relative to [arc_pentesting_framework_2d478447.plan.md](./arc_pentesting_framework_2d478447.plan.md) **Implementation Phases (Refined)**.

---

## Current phase: **Phase 2 (Extended Reconnaissance)** — **Complete**

Phase 2 is fully implemented. All items from the plan are in place and working.

| Plan item | Status | Notes |
|-----------|--------|--------|
| GAU (Wayback Machine URL discovery) | Done | MCP 8006, pipeline + storage, Settings toggle |
| Knockpy (Active subdomain bruteforce) | Done | MCP 8007, pipeline + subdomain storage |
| Kiterunner (API endpoint discovery) | Done | MCP 8008, pipeline + ApiEndpoint storage, scan results tab |
| Wappalyzer (Technology fingerprinting) | Done | MCP 8009, pipeline + Technology storage |
| python-whois (WHOIS lookups) | Done | MCP 8010, pipeline + WhoisData storage, report + UI |
| Shodan InternetDB (Passive recon) | Done | MCP 8011, pipeline + ShodanData storage, report + UI |
| GitHub secret hunting | Done | MCP 8012, pipeline + GitHubRepo/GitHubFinding storage, scan results tabs |
| Continuous monitoring | Done | APScheduler, jobs API, trigger API, Docker |

**Extras (not in plan list but implemented):**

- Pipeline tool selection in **Settings** (checkboxes for all 7 extended tools).
- Report export: WHOIS, Shodan, tech in project/scan reports and PDF.
- Scan results UI: Technologies, WHOIS, Shodan, API endpoints, GitHub repos, GitHub findings tabs.
- Neo4j storage for Kiterunner (ApiEndpoint) and GitHub (GitHubRepo, GitHubFinding).

---

## Phase 1: Foundation + Reconnaissance — **Complete**

All 10 deliverables from the plan are done.

| # | Deliverable | Status |
|---|--------------|--------|
| 1 | Enterprise directory structure | Done |
| 2 | Docker infrastructure (Neo4j, Redis, ELK, Kali sandbox) | Done |
| 3 | Core Python package (config, logging, exceptions) | Done |
| 4 | Neo4j graph schema with attack surface model | Done |
| 5 | MCP servers: Naabu, Httpx, Subfinder, dnsx, Katana, Nuclei | Done (ports 8000–8005) |
| 6 | Recon pipeline orchestrator | Done |
| 7 | FastAPI backend with REST + WebSocket | Done |
| 8 | Mission Control UI (dark minimal) | Done |
| 9 | Real-time scan monitoring | Done |
| 10 | Basic reporting | Done |

---

## Phases 3–6 — **Not started**

| Phase | Scope | Status |
|-------|--------|--------|
| **Phase 3: AI Agent Core** | LLM abstraction, LangGraph, cognitive memory, ReAct nodes, approval gates, Text-to-Cypher | Not started |
| **Phase 4: Attack Intelligence** | Neo4j GDS attack paths, EPSS, MITRE ATT&CK, BloodHound-style paths, risk scoring | Not started |
| **Phase 5: Exploitation** | Metasploit, SQLMap, session management, post-exploit, Sliver C2 | Not started |
| **Phase 6: Advanced Features** | Multi-agent hierarchy, CALDERA, automated reporting (PDF, SARIF), AD/Azure paths, compliance | Not started |

---

## Whole status and percentage

- **Phases complete:** 2 of 6 (Phase 1, Phase 2).
- **Phase completion:** Phase 1 **100%**, Phase 2 **100%**, Phases 3–6 **0%**.

**Overall by phase count:**

- **2 / 6 ≈ 33%** (two phases fully complete).

**Overall by deliverable count (plan items only):**

- Phase 1: 10 deliverables → 10 done.  
- Phase 2: 8 items → 8 done.  
- Phase 3: 6 items, Phase 4: 5, Phase 5: 5, Phase 6: 5 → 0 done.  
- **18 / 39 ≈ 46%** of plan deliverables done.

**Summary:** Current phase (Phase 2) is **complete**. Overall implementation is **~33–46%** of the full plan depending on whether you count by phases or by deliverables.

---

## Next (per plan)

- **Phase 3: AI Agent Core** — LLM abstraction, LangGraph, cognitive memory, ReAct, approval gates, Text-to-Cypher.
