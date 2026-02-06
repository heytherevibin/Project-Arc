"""
Text-to-Cypher

Converts natural language questions to Cypher queries using an LLM.
Validates generated queries before execution and falls back to
predefined queries on failure.
"""

from __future__ import annotations

import re
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)

# Graph schema context injected into the LLM prompt
SCHEMA_CONTEXT = """
Node labels: Host, IP, Vulnerability, Credential, Service, ADUser, ADGroup,
  ADComputer, AzureUser, AzureApp, AzureRole, AzureServicePrincipal,
  GPO, OU, CertificateTemplate, CertificateAuthority, Port, Subdomain,
  EpisodicEvent, CVE, Product, ExploitPattern, FailureRecord, Project, Scan

Relationship types: CAN_REACH, HAS_VULN, CAN_EXPLOIT, GRANTS_ACCESS,
  HAS_CREDENTIAL, MEMBER_OF, ADMIN_TO, HAS_SESSION, CAN_RDPINTO,
  HAS_SPN, GenericAll, WriteDacl, WriteOwner, ForceChangePassword,
  AddMember, GenericWrite, CONTAINS, AppliesTo, RUNS_SERVICE,
  IDENTIFIED_AS, AFFECTS, ISSUED_BY, Owns, HasPermission

Common properties:
  Host: hostname, ip, os, project_id, node_id
  Vulnerability: vuln_id, name, severity, cvss_score, cve_id, project_id
  Credential: username, hash, credential_type, project_id
  ADUser: username, enabled, name, spn, project_id
  Service: name, port, version, project_id
"""

# Dangerous Cypher patterns to block
DANGEROUS_PATTERNS = [
    r"\bDELETE\b",
    r"\bDETACH\b",
    r"\bDROP\b",
    r"\bCREATE\b",
    r"\bSET\b",
    r"\bMERGE\b",
    r"\bREMOVE\b",
    r"\bCALL\s+dbms\b",
]


class TextToCypher:
    """
    Translates natural language questions to Cypher queries.

    Uses an LLM (OpenAI/Anthropic) with schema context injection.
    Validates generated queries for safety before execution.
    Falls back to predefined queries on failure.
    """

    # Predefined fallback queries for common questions
    FALLBACK_QUERIES: dict[str, str] = {
        "hosts": "MATCH (h:Host) RETURN h.hostname, h.ip, h.os LIMIT 50",
        "vulnerabilities": "MATCH (v:Vulnerability) RETURN v.name, v.severity, v.cvss_score ORDER BY v.cvss_score DESC LIMIT 50",
        "critical_vulns": "MATCH (v:Vulnerability) WHERE v.severity = 'critical' RETURN v.name, v.cvss_score, v.cve_id LIMIT 50",
        "credentials": "MATCH (c:Credential) RETURN c.username, c.credential_type LIMIT 50",
        "attack_paths": "MATCH path = (a)-[*1..4]->(b) WHERE a:Host AND b:Host AND a<>b RETURN path LIMIT 20",
        "domain_admins": "MATCH (u:ADUser)-[:MEMBER_OF*1..3]->(g:ADGroup) WHERE g.name =~ '(?i)domain admins.*' RETURN u.username, u.name LIMIT 50",
    }

    def __init__(
        self,
        client: Neo4jClient,
        llm_client: Any | None = None,
    ) -> None:
        self._client = client
        self._llm = llm_client

    async def generate_cypher(
        self,
        question: str,
        project_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Convert a natural language question to a Cypher query.

        Returns
        -------
        dict with keys: query (str), params (dict), source ("llm" | "fallback")
        """
        # Try LLM first if available
        if self._llm:
            try:
                cypher = await self._llm_generate(question, project_id)
                if cypher and self._validate_query(cypher):
                    return {
                        "query": cypher,
                        "params": {"project_id": project_id} if project_id else {},
                        "source": "llm",
                    }
            except Exception as exc:
                logger.warning("LLM Cypher generation failed", error=str(exc))

        # Fallback to predefined queries
        fallback = self._find_fallback(question)
        if fallback:
            params: dict[str, Any] = {}
            if project_id and "$project_id" in fallback:
                params["project_id"] = project_id
            return {"query": fallback, "params": params, "source": "fallback"}

        # Default: basic host query
        return {
            "query": "MATCH (h:Host) RETURN h.hostname, h.ip LIMIT 20",
            "params": {},
            "source": "fallback",
        }

    async def execute(
        self,
        question: str,
        project_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Generate and execute a Cypher query from a natural language question.
        """
        result = await self.generate_cypher(question, project_id)
        query = result["query"]
        params = result["params"]

        logger.info(
            "Executing text-to-cypher",
            source=result["source"],
            query=query[:100],
        )

        records = await self._client.execute_read(query, params)
        return [dict(r) for r in records]

    # ------------------------------------------------------------------
    # LLM generation
    # ------------------------------------------------------------------

    async def _llm_generate(
        self,
        question: str,
        project_id: str | None,
    ) -> str | None:
        """Use LLM to generate Cypher from natural language."""
        prompt = f"""You are a Neo4j Cypher expert. Convert the following natural language
question into a valid Cypher query.

Graph Schema:
{SCHEMA_CONTEXT}

Rules:
- Only generate READ queries (MATCH/RETURN). Never generate write operations.
- Always use LIMIT to cap results (max 100).
- Use parameterised queries where possible ($project_id).
{f'- Filter by project_id = $project_id where applicable.' if project_id else ''}

Question: {question}

Return ONLY the Cypher query, no explanation."""

        # This is a generic interface — the actual LLM client handles the call
        if hasattr(self._llm, "generate"):
            response = await self._llm.generate(prompt)
            return response.strip() if response else None
        if hasattr(self._llm, "ainvoke"):
            response = await self._llm.ainvoke(prompt)
            content = getattr(response, "content", str(response))
            return content.strip() if content else None

        return None

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_query(cypher: str) -> bool:
        """Validate that a generated Cypher query is safe to execute."""
        upper = cypher.upper()

        # Must contain MATCH and RETURN
        if "MATCH" not in upper or "RETURN" not in upper:
            return False

        # Block dangerous operations
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, cypher, re.IGNORECASE):
                logger.warning("Blocked dangerous Cypher", pattern=pattern)
                return False

        return True

    # ------------------------------------------------------------------
    # Fallback matching
    # ------------------------------------------------------------------

    def _find_fallback(self, question: str) -> str | None:
        """Find a predefined query that matches the question keywords."""
        q_lower = question.lower()

        keyword_map = {
            "hosts": ["host", "machine", "server", "computer"],
            "vulnerabilities": ["vuln", "vulnerability", "cve"],
            "critical_vulns": ["critical", "severe"],
            "credentials": ["credential", "password", "hash", "cred"],
            "attack_paths": ["path", "route", "attack path"],
            "domain_admins": ["domain admin", "da ", "admin user"],
        }

        for key, keywords in keyword_map.items():
            if any(kw in q_lower for kw in keywords):
                # Prefer more specific matches
                if key == "critical_vulns" and "critical" in q_lower:
                    return self.FALLBACK_QUERIES["critical_vulns"]
                return self.FALLBACK_QUERIES[key]

        return None
