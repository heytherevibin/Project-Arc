"""
Playbooks - Attack Sequence Templates

Stores and retrieves proven attack sequences (playbooks) that can be
replayed in similar scenarios.  Learned from successful engagements
and used to accelerate future missions.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class PlaybookStep:
    """A single step in an attack playbook."""
    step_number: int
    tool_name: str
    args_template: dict[str, Any]
    expected_output: str = ""
    requires_approval: bool = False
    risk_level: str = "low"
    notes: str = ""


@dataclass
class Playbook:
    """A reusable attack sequence template."""
    playbook_id: str
    name: str
    description: str
    target_type: str            # "web_app", "network", "ad_domain", "cloud", etc.
    phases: list[str]           # Which phases this playbook covers
    steps: list[PlaybookStep] = field(default_factory=list)
    success_count: int = 0
    failure_count: int = 0
    tags: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        return (self.success_count / total) if total > 0 else 0.0


class PlaybookLibrary:
    """
    In-memory playbook library.

    Stores attack sequence templates that can be recommended to agents
    based on the current target type and engagement phase.
    """

    def __init__(self) -> None:
        self._playbooks: dict[str, Playbook] = {}
        self._load_defaults()

    def _load_defaults(self) -> None:
        """Load built-in playbooks for common pentest scenarios."""
        defaults = [
            Playbook(
                playbook_id="pb-web-standard",
                name="Standard Web Application Pentest",
                description="Full recon → vuln scan → exploit flow for web applications",
                target_type="web_app",
                phases=["recon", "vuln_analysis", "exploitation"],
                steps=[
                    PlaybookStep(1, "subfinder", {"target": "{domain}"}, "Subdomains list"),
                    PlaybookStep(2, "httpx", {"targets": "{subdomains}"}, "Live URLs"),
                    PlaybookStep(3, "katana", {"target": "{live_urls}"}, "Crawled endpoints"),
                    PlaybookStep(4, "nuclei", {"targets": "{live_urls}"}, "Vulnerabilities"),
                    PlaybookStep(5, "sqlmap", {"target": "{vuln_url}"}, "SQLi exploitation",
                                 requires_approval=True, risk_level="high"),
                ],
                tags=["web", "standard", "owasp"],
            ),
            Playbook(
                playbook_id="pb-network-recon",
                name="Network Infrastructure Recon",
                description="Port scanning and service enumeration for network targets",
                target_type="network",
                phases=["recon", "vuln_analysis"],
                steps=[
                    PlaybookStep(1, "naabu", {"targets": "{ip_range}"}, "Open ports"),
                    PlaybookStep(2, "httpx", {"targets": "{hosts}"}, "Web services"),
                    PlaybookStep(3, "nuclei", {"targets": "{hosts}"}, "Known CVEs"),
                ],
                tags=["network", "infrastructure"],
            ),
            Playbook(
                playbook_id="pb-ad-attack",
                name="Active Directory Attack Path",
                description="AD enumeration, kerberoasting, and privilege escalation",
                target_type="ad_domain",
                phases=["recon", "exploitation", "post_exploitation", "lateral_movement"],
                steps=[
                    PlaybookStep(1, "bloodhound", {"collection": "All"}, "AD graph data",
                                 requires_approval=True, risk_level="medium"),
                    PlaybookStep(2, "crackmapexec", {"method": "enum"}, "SMB enumeration"),
                    PlaybookStep(3, "impacket", {"attack": "kerberoast"}, "Service tickets",
                                 requires_approval=True, risk_level="high"),
                    PlaybookStep(4, "crackmapexec", {"method": "spray"}, "Password spray",
                                 requires_approval=True, risk_level="critical"),
                ],
                tags=["ad", "identity", "privilege_escalation"],
            ),
        ]
        for pb in defaults:
            self._playbooks[pb.playbook_id] = pb

    def create(
        self,
        name: str,
        description: str,
        target_type: str,
        phases: list[str],
        steps: list[dict[str, Any]] | None = None,
        tags: list[str] | None = None,
    ) -> Playbook:
        """Create a new playbook."""
        playbook = Playbook(
            playbook_id=f"pb-{uuid.uuid4().hex[:8]}",
            name=name,
            description=description,
            target_type=target_type,
            phases=phases,
            tags=tags or [],
        )
        if steps:
            for i, s in enumerate(steps, 1):
                playbook.steps.append(PlaybookStep(
                    step_number=i,
                    tool_name=s.get("tool_name", ""),
                    args_template=s.get("args_template", {}),
                    expected_output=s.get("expected_output", ""),
                    requires_approval=s.get("requires_approval", False),
                    risk_level=s.get("risk_level", "low"),
                ))
        self._playbooks[playbook.playbook_id] = playbook
        return playbook

    def get(self, playbook_id: str) -> Playbook | None:
        return self._playbooks.get(playbook_id)

    def recommend(
        self,
        target_type: str | None = None,
        phase: str | None = None,
        limit: int = 5,
    ) -> list[Playbook]:
        """Recommend playbooks based on target type and current phase."""
        playbooks = list(self._playbooks.values())
        if target_type:
            playbooks = [p for p in playbooks if p.target_type == target_type]
        if phase:
            playbooks = [p for p in playbooks if phase in p.phases]
        playbooks.sort(key=lambda p: p.success_rate, reverse=True)
        return playbooks[:limit]

    def record_outcome(self, playbook_id: str, success: bool) -> None:
        """Record a playbook execution outcome."""
        pb = self._playbooks.get(playbook_id)
        if not pb:
            return
        if success:
            pb.success_count += 1
        else:
            pb.failure_count += 1
        pb.updated_at = datetime.now(timezone.utc).isoformat()

    def list_all(self) -> list[Playbook]:
        return list(self._playbooks.values())
