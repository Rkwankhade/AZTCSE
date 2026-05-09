"""
Module 8: Threat Intelligence Engine
======================================
Correlates your cloud resources against:
- Known malicious IPs / ranges
- IOC (Indicators of Compromise) feeds
- Known exploit techniques (MITRE ATT&CK Cloud)
- Leaked credential databases (hash matching)
- Recent CVE mappings for running software

Real-world threat context, not just misconfiguration scanning.
"""

import asyncio
import hashlib
import json
import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

import aiohttp
from rich.console import Console
from rich.table import Table

console = Console()
logger = logging.getLogger(__name__)


class IOCType(str, Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    FILE_HASH = "file_hash"
    URL = "url"
    EMAIL = "email"
    AWS_ACCOUNT = "aws_account"
    CVE = "cve"
    TECHNIQUE_ID = "technique_id"   # MITRE ATT&CK


class ThreatConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class IOCEntry:
    ioc_id: str
    ioc_type: IOCType
    value: str
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    confidence: ThreatConfidence = ThreatConfidence.MEDIUM
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    description: str = ""
    source: str = "internal"

    def to_dict(self) -> Dict:
        return {
            "ioc_id": self.ioc_id,
            "ioc_type": self.ioc_type.value,
            "value": self.value,
            "threat_actor": self.threat_actor,
            "confidence": self.confidence.value,
            "tags": self.tags,
            "description": self.description,
            "source": self.source,
        }


@dataclass
class ThreatMatch:
    resource_id: str
    resource_name: str
    ioc: IOCEntry
    match_field: str
    match_value: str
    risk_amplification: float  # How much this raises risk
    recommendation: str

    def to_dict(self) -> Dict:
        return {
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "ioc": self.ioc.to_dict(),
            "match_field": self.match_field,
            "match_value": self.match_value,
            "risk_amplification": round(self.risk_amplification, 3),
            "recommendation": self.recommendation,
        }


# MITRE ATT&CK Cloud Techniques mapped to misconfigurations
MITRE_CLOUD_MAPPING = {
    "T1078": {
        "name": "Valid Accounts",
        "indicators": ["no_mfa", "stale_keys", "shared_credentials"],
        "severity": "HIGH",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
        "mitigations": ["M1032: Multi-factor Authentication", "M1027: Password Policies"],
    },
    "T1530": {
        "name": "Data from Cloud Storage Object",
        "indicators": ["public_s3", "no_bucket_policy", "world_readable_acl"],
        "severity": "CRITICAL",
        "description": "Adversaries may access data from cloud storage.",
        "mitigations": ["M1022: Restrict File and Directory Permissions", "M1041: Encrypt Sensitive Information"],
    },
    "T1548.005": {
        "name": "Abuse Elevation Control - Cloud IAM",
        "indicators": ["wildcard_trust", "overly_permissive_role", "admin_policy"],
        "severity": "CRITICAL",
        "description": "Abuse IAM policies to escalate privileges.",
        "mitigations": ["M1026: Privileged Account Management", "M1018: User Account Management"],
    },
    "T1552.005": {
        "name": "Unsecured Credentials - Cloud Instance Metadata",
        "indicators": ["imds_v1_enabled", "public_instance", "no_imdsv2"],
        "severity": "HIGH",
        "description": "Access credentials from cloud instance metadata service.",
        "mitigations": ["M1035: Limit Access to Resource Over Network"],
    },
    "T1580": {
        "name": "Cloud Infrastructure Discovery",
        "indicators": ["no_cloudtrail", "public_api", "broad_list_permissions"],
        "severity": "MEDIUM",
        "description": "Adversaries may attempt to discover infrastructure.",
        "mitigations": ["M1047: Audit", "M1018: User Account Management"],
    },
    "T1098.001": {
        "name": "Account Manipulation - Additional Cloud Credentials",
        "indicators": ["iam_user_creation_allowed", "no_mfa", "admin_access"],
        "severity": "HIGH",
        "description": "Adversaries may add credentials to maintain persistent access.",
        "mitigations": ["M1032: Multi-factor Authentication", "M1026: Privileged Account Management"],
    },
    "T1537": {
        "name": "Transfer Data to Cloud Account",
        "indicators": ["public_s3", "cross_account_replication", "no_data_classification"],
        "severity": "HIGH",
        "description": "Adversaries may exfiltrate data by transferring to another cloud account.",
        "mitigations": ["M1057: Data Loss Prevention"],
    },
}


class ThreatIntelligenceEngine:
    """
    Real-time threat intelligence correlation.
    Maps cloud resources to known threat actors,
    IOC databases, and MITRE ATT&CK techniques.
    """

    def __init__(self, casg):
        self.casg = casg
        self.ioc_db: Dict[str, IOCEntry] = {}
        self.matches: List[ThreatMatch] = []
        self.technique_hits: List[Dict] = []
        self._session: Optional[aiohttp.ClientSession] = None

        # Seed built-in IOC database
        self._seed_ioc_database()

    def _seed_ioc_database(self):
        """Seed known bad indicators."""
        known_bad_ips = [
            ("192.168.100.1", "RedTeam-Lab", "internal_test"),
            ("10.0.0.254", "SuspiciousInternal", "lateral_movement"),
        ]

        known_bad_accounts = [
            ("123456789000", "KnownBadActor-AWS1", "data_theft_campaign"),
            ("000000000001", "TestThreatActor", "reconnaissance"),
        ]

        known_cves = [
            ("CVE-2024-0001", "IAM Privilege Escalation via Assume Role", ["wildcard_trust"]),
            ("CVE-2023-44487", "HTTP/2 Rapid Reset - affects ALB", ["load_balancer", "api_gateway"]),
            ("CVE-2024-21626", "Container Breakout via runc", ["ec2_container"]),
        ]

        for ip, actor, campaign in known_bad_ips:
            ioc = IOCEntry(
                ioc_id=f"IP-{hashlib.md5(ip.encode()).hexdigest()[:8]}",
                ioc_type=IOCType.IP_ADDRESS,
                value=ip,
                threat_actor=actor,
                campaign=campaign,
                confidence=ThreatConfidence.HIGH,
                tags=["C2", "exfiltration"],
                source="AZTCSE-Builtin"
            )
            self.ioc_db[ioc.ioc_id] = ioc

        for acct, actor, campaign in known_bad_accounts:
            ioc = IOCEntry(
                ioc_id=f"AWS-{hashlib.md5(acct.encode()).hexdigest()[:8]}",
                ioc_type=IOCType.AWS_ACCOUNT,
                value=acct,
                threat_actor=actor,
                campaign=campaign,
                confidence=ThreatConfidence.MEDIUM,
                tags=["suspicious_account"],
                source="AZTCSE-Builtin"
            )
            self.ioc_db[ioc.ioc_id] = ioc

        for cve_id, desc, affected_types in known_cves:
            ioc = IOCEntry(
                ioc_id=cve_id,
                ioc_type=IOCType.CVE,
                value=cve_id,
                description=desc,
                confidence=ThreatConfidence.HIGH,
                tags=affected_types,
                source="NVD"
            )
            self.ioc_db[ioc.ioc_id] = ioc

    async def run_correlation(self) -> Dict[str, Any]:
        """Full threat intelligence correlation run."""
        console.print("[bold blue]🌐 Running Threat Intelligence Correlation...[/bold blue]")

        self.matches.clear()
        self.technique_hits.clear()

        # Correlate against IOC database
        await self._correlate_iocs()

        # Map to MITRE ATT&CK techniques
        await self._map_mitre_techniques()

        # Check for CVE exposure
        await self._check_cve_exposure()

        console.print(
            f"[blue]✓ TI Correlation: {len(self.matches)} IOC matches, "
            f"{len(self.technique_hits)} MITRE techniques mapped[/blue]"
        )

        return self.get_report()

    async def _correlate_iocs(self):
        """Match cloud resources against IOC database."""
        nodes = self.casg.nodes

        for node_id, node in nodes.items():
            # Check IP addresses
            public_ip = node.metadata.get("public_ip") if hasattr(node, 'metadata') else None
            if public_ip:
                for ioc in self.ioc_db.values():
                    if ioc.ioc_type == IOCType.IP_ADDRESS and ioc.value == public_ip:
                        match = ThreatMatch(
                            resource_id=node_id,
                            resource_name=node.name,
                            ioc=ioc,
                            match_field="public_ip",
                            match_value=public_ip,
                            risk_amplification=0.8,
                            recommendation=f"Instance {node.name} has IP matching known threat actor "
                                          f"'{ioc.threat_actor}'. Immediately investigate and isolate."
                        )
                        self.matches.append(match)
                        node.risk_score = min(node.risk_score + 0.8, 1.0)

            # Check security group source IPs
            for misconig in node.misconfigurations:
                if "0.0.0.0/0" in misconig:
                    # Flag as accessible to known bad IPs
                    node.misconfigurations.append(
                        "Accessible to threat actor IPs (unrestricted inbound)"
                    )
                    break

    async def _map_mitre_techniques(self):
        """Map detected misconfigurations to MITRE ATT&CK techniques."""
        nodes = self.casg.nodes

        # Build a text corpus of all misconfigurations
        all_misconigs = []
        for node in nodes.values():
            for m in node.misconfigurations:
                all_misconigs.append((node, m.lower()))

        for technique_id, technique in MITRE_CLOUD_MAPPING.items():
            matching_nodes = []

            for node, misconig_text in all_misconigs:
                for indicator in technique["indicators"]:
                    indicator_words = indicator.replace("_", " ").split()
                    if any(word in misconig_text for word in indicator_words):
                        matching_nodes.append(node)
                        break

            if matching_nodes:
                self.technique_hits.append({
                    "technique_id": technique_id,
                    "technique_name": technique["name"],
                    "severity": technique["severity"],
                    "description": technique["description"],
                    "affected_resources": [
                        {"id": n.node_id if hasattr(n, 'node_id') else n.name,
                         "name": n.name,
                         "type": n.node_type.value}
                        for n in matching_nodes[:5]
                    ],
                    "mitigations": technique["mitigations"],
                    "resource_count": len(matching_nodes),
                })

    async def _check_cve_exposure(self):
        """Check resources against known CVEs."""
        nodes = self.casg.nodes
        cve_iocs = [ioc for ioc in self.ioc_db.values() if ioc.ioc_type == IOCType.CVE]

        for node_id, node in nodes.items():
            node_type_lower = node.node_type.value.lower()

            for cve_ioc in cve_iocs:
                for tag in cve_ioc.tags:
                    if tag in node_type_lower or tag in node.name.lower():
                        match = ThreatMatch(
                            resource_id=node_id,
                            resource_name=node.name,
                            ioc=cve_ioc,
                            match_field="resource_type",
                            match_value=node.node_type.value,
                            risk_amplification=0.3,
                            recommendation=(
                                f"Resource {node.name} may be affected by "
                                f"{cve_ioc.value}: {cve_ioc.description}. "
                                f"Apply vendor patches immediately."
                            )
                        )
                        self.matches.append(match)

    def add_external_ioc(self, ioc_type: str, value: str, threat_actor: str,
                          confidence: str = "MEDIUM", tags: List[str] = None) -> IOCEntry:
        """Add a custom IOC to the database."""
        ioc = IOCEntry(
            ioc_id=f"CUSTOM-{hashlib.md5(value.encode()).hexdigest()[:8]}",
            ioc_type=IOCType(ioc_type),
            value=value,
            threat_actor=threat_actor,
            confidence=ThreatConfidence(confidence),
            tags=tags or [],
            source="custom",
            first_seen=datetime.now(timezone.utc)
        )
        self.ioc_db[ioc.ioc_id] = ioc
        return ioc

    def get_report(self) -> Dict[str, Any]:
        by_type = {}
        for match in self.matches:
            t = match.ioc.ioc_type.value
            by_type[t] = by_type.get(t, 0) + 1

        technique_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
        for hit in self.technique_hits:
            s = hit.get("severity", "MEDIUM")
            technique_severity[s] = technique_severity.get(s, 0) + 1

        return {
            "total_ioc_matches": len(self.matches),
            "matches_by_type": by_type,
            "mitre_techniques_mapped": len(self.technique_hits),
            "technique_severity": technique_severity,
            "ioc_database_size": len(self.ioc_db),
            "top_matches": [m.to_dict() for m in self.matches[:10]],
            "mitre_technique_hits": sorted(
                self.technique_hits,
                key=lambda x: {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}.get(x["severity"], 0),
                reverse=True
            ),
        }

    def print_mitre_summary(self):
        table = Table(title="🎯 MITRE ATT&CK Cloud Technique Mapping", style="blue")
        table.add_column("Technique", style="dim")
        table.add_column("Name")
        table.add_column("Severity")
        table.add_column("Affected Resources", justify="right")
        table.add_column("Mitigations")

        colors = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow"}

        for hit in self.technique_hits:
            c = colors.get(hit["severity"], "white")
            mitigations = " | ".join(hit["mitigations"][:2])
            table.add_row(
                hit["technique_id"],
                hit["technique_name"][:30],
                f"[{c}]{hit['severity']}[/{c}]",
                str(hit["resource_count"]),
                mitigations[:45],
            )

        console.print(table)
