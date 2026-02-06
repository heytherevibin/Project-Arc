// =============================================================================
// Arc - Neo4j Core Schema
// Attack Surface Graph Schema with Multi-Tenant Support
// =============================================================================
// Run this script to initialize the database schema.
// Constraints and indexes are in indexes.cypher (run after this file).
// =============================================================================

// =============================================================================
// RELATIONSHIP TYPE DESCRIPTIONS (Documentation)
// =============================================================================

// Domain Hierarchy:
// (Domain)-[:HAS_SUBDOMAIN]->(Subdomain)
// (Subdomain)-[:RESOLVES_TO]->(IP)
// (Subdomain)-[:HAS_DNS_RECORD]->(DNSRecord)

// Network Hierarchy:
// (IP)-[:HAS_PORT]->(Port)
// (Port)-[:RUNS_SERVICE]->(Service)

// Web Hierarchy:
// (Service)-[:SERVES_URL]->(URL)
// (URL)-[:HAS_ENDPOINT]->(Endpoint)
// (Endpoint)-[:HAS_PARAMETER]->(Parameter)

// Technology Detection:
// (URL)-[:USES_TECHNOLOGY]->(Technology)
// (Service)-[:USES_TECHNOLOGY]->(Technology)

// Vulnerability Linkage:
// (URL)-[:HAS_VULNERABILITY]->(Vulnerability)
// (Endpoint)-[:HAS_VULNERABILITY]->(Vulnerability)
// (Parameter)-[:HAS_VULNERABILITY]->(Vulnerability)
// (Vulnerability)-[:ASSOCIATED_CVE]->(CVE)

// Certificate:
// (URL)-[:HAS_CERTIFICATE]->(Certificate)

// Scan Tracking:
// (Scan)-[:DISCOVERED]->(Any Node)
// (Scan)-[:TARGETS]->(Domain|IP|URL)

// =============================================================================
// Extended recon (WhoisData, ShodanData)
// =============================================================================
// Constraints/indexes for WhoisData, ShodanData, ApiEndpoint, GitHubRepo,
// GitHubFinding are in indexes.cypher.

// Extended recon relationships:
// (Domain)-[:HAS_WHOIS]->(WhoisData)
// (IP)-[:HAS_SHODAN_DATA]->(ShodanData)

// =============================================================================
// Kiterunner (ApiEndpoint) and GitHub recon (GitHubRepo, GitHubFinding)
// =============================================================================
// Kiterunner: (URL)-[:HAS_ENDPOINT]->(ApiEndpoint), (Scan)-[:DISCOVERED]->(ApiEndpoint)
// GitHub: (Domain)-[:HAS_GITHUB_REPO]->(GitHubRepo), (Scan)-[:DISCOVERED]->(GitHubRepo)
// (Scan)-[:DISCOVERED]->(GitHubFinding)
