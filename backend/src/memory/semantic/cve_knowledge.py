"""
CVE Knowledge Store

Stores CVE details, exploit references, and affected products in Neo4j.
Links :CVE nodes to :Vulnerability and :Host nodes for contextual
retrieval during vulnerability analysis and exploitation planning.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


@dataclass
class CVERecord:
    """A CVE knowledge record."""
    cve_id: str
    description: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity: str = "unknown"
    affected_products: list[str] = field(default_factory=list)
    exploit_refs: list[str] = field(default_factory=list)
    published: str = ""
    modified: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    epss_score: float | None = None


class CVEKnowledge:
    """
    CVE knowledge base backed by Neo4j.

    Manages :CVE nodes linked to :Vulnerability, :Host, and :Product nodes
    for enrichment during exploit planning.
    """

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    # ------------------------------------------------------------------
    # Store / Update
    # ------------------------------------------------------------------

    async def store_cve(self, record: CVERecord) -> str:
        """
        Upsert a CVE record into Neo4j.

        Creates a :CVE node and links to :Product nodes.
        Returns the CVE ID.
        """
        query = """
        MERGE (c:CVE {cve_id: $cve_id})
        SET c.description   = $description,
            c.cvss_score    = $cvss_score,
            c.cvss_vector   = $cvss_vector,
            c.severity      = $severity,
            c.published     = $published,
            c.modified      = $modified,
            c.cwe_ids       = $cwe_ids,
            c.exploit_refs  = $exploit_refs,
            c.epss_score    = $epss_score
        RETURN c.cve_id AS cve_id
        """
        params = {
            "cve_id": record.cve_id,
            "description": record.description,
            "cvss_score": record.cvss_score,
            "cvss_vector": record.cvss_vector,
            "severity": record.severity,
            "published": record.published,
            "modified": record.modified,
            "cwe_ids": record.cwe_ids,
            "exploit_refs": record.exploit_refs,
            "epss_score": record.epss_score,
        }
        await self._client.execute_write(query, params)

        # Link to products
        for product in record.affected_products:
            await self._link_product(record.cve_id, product)

        logger.debug("CVE stored", cve_id=record.cve_id)
        return record.cve_id

    async def _link_product(self, cve_id: str, product: str) -> None:
        query = """
        MATCH (c:CVE {cve_id: $cve_id})
        MERGE (p:Product {name: $product})
        MERGE (c)-[:AFFECTS]->(p)
        """
        await self._client.execute_write(query, {"cve_id": cve_id, "product": product})

    async def link_to_vulnerability(self, cve_id: str, vuln_id: str) -> None:
        """Link a CVE node to an existing :Vulnerability node."""
        query = """
        MATCH (c:CVE {cve_id: $cve_id})
        MATCH (v:Vulnerability {vuln_id: $vuln_id})
        MERGE (v)-[:IDENTIFIED_AS]->(c)
        """
        await self._client.execute_write(query, {"cve_id": cve_id, "vuln_id": vuln_id})

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    async def search_by_product(
        self,
        product: str,
        min_cvss: float = 0.0,
        limit: int = 20,
    ) -> list[CVERecord]:
        """Find CVEs affecting a product, sorted by CVSS score descending."""
        query = """
        MATCH (c:CVE)-[:AFFECTS]->(p:Product)
        WHERE p.name CONTAINS $product AND c.cvss_score >= $min_cvss
        RETURN c
        ORDER BY c.cvss_score DESC
        LIMIT $limit
        """
        records = await self._client.execute_read(
            query, {"product": product, "min_cvss": min_cvss, "limit": limit},
        )
        return [self._to_record(r["c"]) for r in records]

    async def get_exploits_for_cve(self, cve_id: str) -> list[str]:
        """Return known exploit references for a CVE."""
        query = """
        MATCH (c:CVE {cve_id: $cve_id})
        RETURN c.exploit_refs AS refs
        """
        records = await self._client.execute_read(query, {"cve_id": cve_id})
        if records:
            return records[0].get("refs", []) or []
        return []

    async def get_cve(self, cve_id: str) -> CVERecord | None:
        """Retrieve a single CVE record by ID."""
        query = """
        MATCH (c:CVE {cve_id: $cve_id})
        OPTIONAL MATCH (c)-[:AFFECTS]->(p:Product)
        RETURN c, collect(p.name) AS products
        """
        records = await self._client.execute_read(query, {"cve_id": cve_id})
        if not records:
            return None
        row = records[0]
        rec = self._to_record(row["c"])
        rec.affected_products = row.get("products", [])
        return rec

    async def enrich_from_nvd(self, cve_id: str) -> CVERecord | None:
        """
        Enrich a CVE record from the NVD API (stub — network calls
        are done by the caller; this persists the enriched data).

        Returns the existing record for the caller to populate and
        re-store via ``store_cve()``.
        """
        return await self.get_cve(cve_id)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_record(node: Any) -> CVERecord:
        props = dict(node) if hasattr(node, "__iter__") else {}
        return CVERecord(
            cve_id=props.get("cve_id", ""),
            description=props.get("description", ""),
            cvss_score=float(props.get("cvss_score", 0)),
            cvss_vector=props.get("cvss_vector", ""),
            severity=props.get("severity", "unknown"),
            affected_products=props.get("affected_products", []),
            exploit_refs=props.get("exploit_refs", []),
            published=props.get("published", ""),
            modified=props.get("modified", ""),
            cwe_ids=props.get("cwe_ids", []),
            epss_score=props.get("epss_score"),
        )
