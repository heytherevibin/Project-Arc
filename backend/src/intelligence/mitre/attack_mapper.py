"""
MITRE ATT&CK Mapper

Maps agent actions and tool executions to MITRE ATT&CK techniques,
generates attack narratives, and calculates coverage metrics.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


@dataclass
class Technique:
    """A MITRE ATT&CK technique."""
    technique_id: str
    name: str
    tactic: str = ""
    description: str = ""


@dataclass
class TacticPhase:
    """A phase in the attack mapped to a tactic."""
    tactic: str
    techniques: list[Technique]
    timestamp: str | None = None


@dataclass
class AttackNarrative:
    """ATT&CK-aligned attack narrative for reporting."""
    kill_chain: list[TacticPhase]
    techniques_used: int
    tactics_covered: int
    coverage_score: float  # 0-1 percentage of ATT&CK tactics covered


class MITREAttackMapper:
    """
    Maps agent actions to MITRE ATT&CK framework.
    Enables adversary emulation and coverage analysis.
    """

    # Tool → ATT&CK technique mapping
    TOOL_TECHNIQUE_MAP: dict[str, list[Technique]] = {
        "subfinder": [
            Technique("T1596.002", "Search Open Technical Databases: DNS/Passive DNS", "Reconnaissance"),
        ],
        "naabu": [
            Technique("T1046", "Network Service Discovery", "Discovery"),
        ],
        "httpx": [
            Technique("T1595.002", "Active Scanning: Vulnerability Scanning", "Reconnaissance"),
        ],
        "katana": [
            Technique("T1595.003", "Active Scanning: Wordlist Scanning", "Reconnaissance"),
        ],
        "nuclei": [
            Technique("T1595.002", "Active Scanning: Vulnerability Scanning", "Reconnaissance"),
        ],
        "shodan": [
            Technique("T1596.005", "Search Open Technical Databases: Scan Databases", "Reconnaissance"),
        ],
        "whois": [
            Technique("T1596.002", "Search Open Technical Databases: WHOIS", "Reconnaissance"),
        ],
        "github_recon": [
            Technique("T1593.003", "Search Open Websites/Domains: Code Repositories", "Reconnaissance"),
        ],
        "bloodhound": [
            Technique("T1087.002", "Account Discovery: Domain Account", "Discovery"),
            Technique("T1069.002", "Permission Groups Discovery: Domain Groups", "Discovery"),
            Technique("T1018", "Remote System Discovery", "Discovery"),
        ],
        "metasploit": [
            Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
        ],
        "sqlmap": [
            Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
        ],
        "credential_dump": [
            Technique("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access"),
        ],
        "kerberoast": [
            Technique("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", "Credential Access"),
        ],
        "dcsync": [
            Technique("T1003.006", "OS Credential Dumping: DCSync", "Credential Access"),
        ],
        "impacket": [
            Technique("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
            Technique("T1569.002", "System Services: Service Execution", "Execution"),
        ],
        "crackmapexec": [
            Technique("T1110.003", "Brute Force: Password Spraying", "Credential Access"),
            Technique("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
        ],
        "sliver": [
            Technique("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
            Technique("T1573", "Encrypted Channel", "Command and Control"),
        ],
        "certipy": [
            Technique("T1649", "Steal or Forge Authentication Certificates", "Credential Access"),
        ],
    }

    ALL_TACTICS = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact",
    ]

    def __init__(self, neo4j_client: Neo4jClient | None = None) -> None:
        self._client = neo4j_client

    def map_tool_to_techniques(self, tool_name: str) -> list[Technique]:
        """Map a tool execution to ATT&CK techniques."""
        return self.TOOL_TECHNIQUE_MAP.get(tool_name, [])

    def generate_narrative(
        self,
        execution_trace: list[dict[str, Any]],
    ) -> AttackNarrative:
        """Generate ATT&CK-aligned attack narrative from execution trace."""
        tactics_used: dict[str, list[Technique]] = defaultdict(list)

        for step in execution_trace:
            tool_name = step.get("tool_name", "")
            techniques = self.map_tool_to_techniques(tool_name)
            for tech in techniques:
                if tech not in tactics_used[tech.tactic]:
                    tactics_used[tech.tactic].append(tech)

        kill_chain = [
            TacticPhase(
                tactic=tactic,
                techniques=techs,
                timestamp=None,
            )
            for tactic, techs in sorted(
                tactics_used.items(),
                key=lambda x: self.ALL_TACTICS.index(x[0]) if x[0] in self.ALL_TACTICS else 99,
            )
        ]

        total_techniques = sum(len(phase.techniques) for phase in kill_chain)
        coverage = len(tactics_used) / len(self.ALL_TACTICS)

        return AttackNarrative(
            kill_chain=kill_chain,
            techniques_used=total_techniques,
            tactics_covered=len(tactics_used),
            coverage_score=round(coverage, 3),
        )

    async def store_execution_step(
        self,
        project_id: str,
        scan_id: str,
        step_id: str,
        tool_name: str,
        success: bool,
    ) -> None:
        """Store an execution step with ATT&CK mappings in Neo4j."""
        if not self._client:
            return

        techniques = self.map_tool_to_techniques(tool_name)
        for tech in techniques:
            await self._client.execute_write(
                """
                MERGE (e:ExecutionStep {step_id: $step_id, project_id: $pid})
                ON CREATE SET
                    e.tool_name = $tool,
                    e.success = $success,
                    e.executed_at = datetime()
                WITH e
                MERGE (t:MITRETechnique {technique_id: $tech_id})
                ON CREATE SET t.name = $tech_name
                MERGE (e)-[:MAPS_TO_TECHNIQUE]->(t)
                """,
                {
                    "step_id": step_id,
                    "pid": project_id,
                    "tool": tool_name,
                    "success": success,
                    "tech_id": tech.technique_id,
                    "tech_name": tech.name,
                },
            )
