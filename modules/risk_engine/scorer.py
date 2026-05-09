"""
Module 3: Dynamic Risk Scoring Engine
======================================
Context-aware, combinational risk scoring.
NOT static CVSS - understands chains:
"S3 bucket open" + "Admin role exposed" = CRITICAL chain

Uses Graph Neural Network concepts for combinational scoring.
"""

import math
import logging
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

import numpy as np
import networkx as nx
from rich.console import Console
from rich.table import Table

console = Console()
logger = logging.getLogger(__name__)


class RiskCategory(str, Enum):
    EXPOSURE = "exposure"           # Public-facing resources
    PRIVILEGE = "privilege"         # IAM misconfigurations
    DATA = "data"                   # Data at risk
    NETWORK = "network"             # Network misconfigs
    CRYPTOGRAPHIC = "cryptographic" # Encryption issues
    LOGGING = "logging"             # Audit trail gaps
    CHAIN = "chain"                 # Combined risk chains


@dataclass
class RiskFinding:
    """Individual risk finding."""
    finding_id: str
    resource_id: str
    resource_name: str
    category: RiskCategory
    title: str
    description: str
    base_score: float          # 0.0 - 1.0
    context_multiplier: float  # Modified by context
    final_score: float         # base * multiplier
    severity: str              # INFO / LOW / MEDIUM / HIGH / CRITICAL
    remediation: str
    chain_ids: List[str] = field(default_factory=list)  # Related findings
    cvss_vector: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "finding_id": self.finding_id,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "base_score": round(self.base_score, 3),
            "context_multiplier": round(self.context_multiplier, 3),
            "final_score": round(self.final_score, 3),
            "severity": self.severity,
            "remediation": self.remediation,
            "chain_ids": self.chain_ids,
        }


@dataclass
class RiskChain:
    """A chain of related misconfigurations that amplify each other."""
    chain_id: str
    name: str
    findings: List[RiskFinding]
    chain_score: float
    description: str
    attack_scenario: str

    def to_dict(self) -> Dict:
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "findings": [f.to_dict() for f in self.findings],
            "chain_score": round(self.chain_score, 3),
            "description": self.description,
            "attack_scenario": self.attack_scenario,
            "severity": score_to_severity(self.chain_score),
        }


def score_to_severity(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    elif score >= 0.65:
        return "HIGH"
    elif score >= 0.40:
        return "MEDIUM"
    elif score >= 0.20:
        return "LOW"
    return "INFO"


class DynamicRiskEngine:
    """
    Context-aware risk scoring engine.
    
    Key principle: Risk is COMBINATIONAL, not isolated.
    A public S3 bucket alone = HIGH
    A public S3 bucket + no encryption + admin role can access = CRITICAL
    
    The engine models these chains explicitly.
    """

    def __init__(self, casg):
        self.casg = casg
        self.findings: List[RiskFinding] = []
        self.chains: List[RiskChain] = []
        self._finding_counter = 0

    def _next_id(self, prefix: str) -> str:
        self._finding_counter += 1
        return f"{prefix}-{self._finding_counter:04d}"

    async def run_full_analysis(self) -> Dict[str, Any]:
        """Run complete risk analysis on the cloud graph."""
        console.print("[bold yellow]⚡ Running Dynamic Risk Analysis...[/bold yellow]")
        
        self.findings.clear()
        self.chains.clear()
        
        # Individual resource findings
        await self._analyze_iam_risks()
        await self._analyze_network_risks()
        await self._analyze_data_risks()
        await self._analyze_logging_risks()
        
        # Chain analysis (the magic)
        await self._detect_risk_chains()
        
        # Update node risk scores in graph
        await self._update_node_risk_scores()
        
        return self.get_report()

    async def _analyze_iam_risks(self):
        """Analyze IAM misconfigurations."""
        nodes = self.casg.nodes
        graph = self.casg.nx_graph
        
        for node_id, node in nodes.items():
            if node.node_type.value not in ['IAM_USER', 'IAM_ROLE', 'IAM_POLICY']:
                continue
            
            for misconig in node.misconfigurations:
                # Classify the misconfiguration
                if "MFA" in misconig:
                    finding = RiskFinding(
                        finding_id=self._next_id("IAM"),
                        resource_id=node_id,
                        resource_name=node.name,
                        category=RiskCategory.PRIVILEGE,
                        title="Console Access Without MFA",
                        description=f"User {node.name} has console access but MFA is not enabled. "
                                   f"This significantly increases account takeover risk.",
                        base_score=0.65,
                        context_multiplier=1.0,
                        final_score=0.65,
                        severity="HIGH",
                        remediation="Enable MFA for all IAM users with console access. "
                                   "Use aws iam create-virtual-mfa-device and associate it.",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
                    )
                    self.findings.append(finding)
                
                elif "access key" in misconig.lower() and "90 days" in misconig:
                    finding = RiskFinding(
                        finding_id=self._next_id("IAM"),
                        resource_id=node_id,
                        resource_name=node.name,
                        category=RiskCategory.PRIVILEGE,
                        title="Stale Access Keys",
                        description=misconig,
                        base_score=0.45,
                        context_multiplier=1.0,
                        final_score=0.45,
                        severity="MEDIUM",
                        remediation="Rotate access keys every 90 days. "
                                   "Use: aws iam update-access-key --status Inactive",
                    )
                    self.findings.append(finding)
                
                elif "Admin" in misconig or "FullAccess" in misconig:
                    finding = RiskFinding(
                        finding_id=self._next_id("IAM"),
                        resource_id=node_id,
                        resource_name=node.name,
                        category=RiskCategory.PRIVILEGE,
                        title="Overly Permissive Policy",
                        description=misconig,
                        base_score=0.75,
                        context_multiplier=1.0,
                        final_score=0.75,
                        severity="HIGH",
                        remediation="Apply principle of least privilege. "
                                   "Replace AdministratorAccess with scoped policies.",
                    )
                    self.findings.append(finding)
                
                elif "wildcard trust" in misconig.lower() or "ANY AWS" in misconig:
                    finding = RiskFinding(
                        finding_id=self._next_id("IAM"),
                        resource_id=node_id,
                        resource_name=node.name,
                        category=RiskCategory.PRIVILEGE,
                        title="Wildcard Trust Policy",
                        description=f"IAM Role {node.name} can be assumed by ANY AWS principal. "
                                   f"This is a critical misconfiguration.",
                        base_score=0.90,
                        context_multiplier=1.0,
                        final_score=0.90,
                        severity="CRITICAL",
                        remediation="Update trust policy to specify exact ARNs. "
                                   "Never use Principal: '*' in trust policies.",
                    )
                    self.findings.append(finding)

    async def _analyze_network_risks(self):
        """Analyze network and security group misconfigurations."""
        nodes = self.casg.nodes
        
        for node_id, node in nodes.items():
            if node.node_type.value not in ['SECURITY_GROUP', 'EC2_INSTANCE']:
                continue
            
            for misconig in node.misconfigurations:
                if "0.0.0.0/0" in misconig or "open to world" in misconig.lower():
                    is_critical_port = any(p in misconig for p in ["22", "3389", "3306", "5432"])
                    
                    finding = RiskFinding(
                        finding_id=self._next_id("NET"),
                        resource_id=node_id,
                        resource_name=node.name,
                        category=RiskCategory.NETWORK,
                        title="Unrestricted Inbound Traffic",
                        description=misconig,
                        base_score=0.85 if is_critical_port else 0.55,
                        context_multiplier=1.0,
                        final_score=0.85 if is_critical_port else 0.55,
                        severity="CRITICAL" if is_critical_port else "HIGH",
                        remediation=f"Restrict inbound access to specific trusted CIDR ranges. "
                                   f"Run: aws ec2 revoke-security-group-ingress with 0.0.0.0/0",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                    )
                    self.findings.append(finding)
                
                elif "Public IP" in misconig:
                    finding = RiskFinding(
                        finding_id=self._next_id("NET"),
                        resource_id=node_id,
                        resource_name=node.name,
                        category=RiskCategory.EXPOSURE,
                        title="Instance Directly Internet Exposed",
                        description=f"{node.name} has a public IP address, making it directly accessible.",
                        base_score=0.40,
                        context_multiplier=1.0,
                        final_score=0.40,
                        severity="MEDIUM",
                        remediation="Use private subnets with NAT Gateway for EC2 instances. "
                                   "Place instances behind a load balancer.",
                    )
                    self.findings.append(finding)

    async def _analyze_data_risks(self):
        """Analyze data security risks."""
        nodes = self.casg.nodes
        
        for node_id, node in nodes.items():
            if node.node_type.value not in ['S3_BUCKET', 'RDS_INSTANCE']:
                continue
            
            for misconig in node.misconfigurations:
                if "PUBLIC" in misconig or "public" in misconig:
                    perm = "WRITE" if "WRITE" in misconig else "READ"
                    finding = RiskFinding(
                        finding_id=self._next_id("DATA"),
                        resource_id=node_id,
                        resource_name=node.name,
                        category=RiskCategory.DATA,
                        title=f"Publicly Accessible Storage ({perm})",
                        description=f"S3 Bucket {node.name} is publicly accessible with {perm} permission. "
                                   f"Any internet user can {'modify' if perm == 'WRITE' else 'read'} this data.",
                        base_score=0.95 if perm == "WRITE" else 0.75,
                        context_multiplier=1.0,
                        final_score=0.95 if perm == "WRITE" else 0.75,
                        severity="CRITICAL",
                        remediation="Enable S3 Block Public Access: "
                                   "aws s3api put-public-access-block --bucket BUCKET "
                                   "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
                                   "BlockPublicPolicy=true,RestrictPublicBuckets=true",
                    )
                    self.findings.append(finding)
                
                elif "encryption" in misconig.lower():
                    finding = RiskFinding(
                        finding_id=self._next_id("CRYPT"),
                        resource_id=node_id,
                        resource_name=node.name,
                        category=RiskCategory.CRYPTOGRAPHIC,
                        title="Data at Rest Not Encrypted",
                        description=f"{node.name} does not have encryption configured.",
                        base_score=0.35,
                        context_multiplier=1.0,
                        final_score=0.35,
                        severity="MEDIUM",
                        remediation="Enable server-side encryption: "
                                   "aws s3api put-bucket-encryption with AES256 or aws:kms",
                    )
                    self.findings.append(finding)
                
                elif "Versioning" in misconig:
                    finding = RiskFinding(
                        finding_id=self._next_id("DATA"),
                        resource_id=node_id,
                        resource_name=node.name,
                        category=RiskCategory.DATA,
                        title="Versioning Not Enabled",
                        description="S3 bucket versioning not enabled. Data deletion/ransomware not recoverable.",
                        base_score=0.20,
                        context_multiplier=1.0,
                        final_score=0.20,
                        severity="LOW",
                        remediation="aws s3api put-bucket-versioning --versioning-configuration Status=Enabled",
                    )
                    self.findings.append(finding)

    async def _analyze_logging_risks(self):
        """Check for logging and audit trail gaps."""
        # Check if CloudTrail is present
        has_cloudtrail = any(
            n.node_type.value == 'CLOUDTRAIL' 
            for n in self.casg.nodes.values()
        )
        
        if not has_cloudtrail:
            finding = RiskFinding(
                finding_id=self._next_id("LOG"),
                resource_id="cloudtrail-missing",
                resource_name="CloudTrail",
                category=RiskCategory.LOGGING,
                title="CloudTrail Not Enabled",
                description="No CloudTrail trail found. All API activity is unlogged. "
                           "Attackers can operate without any audit trail.",
                base_score=0.70,
                context_multiplier=1.0,
                final_score=0.70,
                severity="HIGH",
                remediation="aws cloudtrail create-trail --name main-trail "
                           "--s3-bucket-name your-cloudtrail-bucket --is-multi-region-trail",
            )
            self.findings.append(finding)

    async def _detect_risk_chains(self):
        """
        THE KEY INNOVATION: Detect chains of misconfigurations 
        that multiply each other's risk.
        """
        graph = self.casg.nx_graph
        nodes = self.casg.nodes
        
        # Chain 1: Public bucket + Admin role with access = CRITICAL chain
        public_buckets = [
            f for f in self.findings 
            if f.category == RiskCategory.DATA and "Publicly" in f.title
        ]
        admin_issues = [
            f for f in self.findings 
            if f.category == RiskCategory.PRIVILEGE and "Admin" in f.title
        ]
        
        if public_buckets and admin_issues:
            chain_score = 0.98  # Near-certain catastrophe
            chain = RiskChain(
                chain_id=self._next_id("CHAIN"),
                name="Data Breach Highway",
                findings=public_buckets[:2] + admin_issues[:2],
                chain_score=chain_score,
                description="Public S3 bucket exposed + admin IAM misconfiguration creates "
                           "a direct path for complete data exfiltration and account takeover.",
                attack_scenario="Attacker finds public bucket → discovers AWS account ID → "
                               "targets admin role via social engineering → full account compromise"
            )
            self.chains.append(chain)
            
            # Update multipliers on component findings
            for f in chain.findings:
                f.context_multiplier = 1.5
                f.final_score = min(f.base_score * 1.5, 1.0)
                f.chain_ids.append(chain.chain_id)
        
        # Chain 2: No MFA + SSH open + admin access
        no_mfa = [f for f in self.findings if "MFA" in f.title]
        ssh_open = [f for f in self.findings if "22" in f.description or "SSH" in f.description]
        
        if no_mfa and ssh_open:
            chain_score = 0.92
            chain = RiskChain(
                chain_id=self._next_id("CHAIN"),
                name="Account Takeover & Server Compromise",
                findings=no_mfa[:1] + ssh_open[:1],
                chain_score=chain_score,
                description="Account without MFA + SSH exposed to internet creates "
                           "trivial path to full server compromise via credential stuffing.",
                attack_scenario="Attacker brute-forces credentials (no MFA to stop them) → "
                               "SSH into exposed server → lateral movement"
            )
            self.chains.append(chain)
        
        # Chain 3: Wildcard trust + public resource = privilege escalation highway
        wildcard = [f for f in self.findings if "Wildcard Trust" in f.title]
        public_access = [f for f in self.findings if f.category == RiskCategory.EXPOSURE]
        
        if wildcard and public_access:
            chain_score = 0.96
            chain = RiskChain(
                chain_id=self._next_id("CHAIN"),
                name="Privilege Escalation Highway",
                findings=wildcard[:1] + public_access[:1],
                chain_score=chain_score,
                description="Wildcard trust policy + public-facing resource means "
                           "any attacker can assume high-privilege roles.",
                attack_scenario="External attacker reaches public resource → "
                               "assumes role with wildcard trust → full admin access"
            )
            self.chains.append(chain)
        
        # Chain 4: No logging + any other finding = stealth attack possible
        no_logging = [f for f in self.findings if f.category == RiskCategory.LOGGING]
        if no_logging and len(self.findings) > 2:
            # Amplify all other findings because attacker has stealth
            for finding in self.findings:
                if finding.category != RiskCategory.LOGGING:
                    finding.context_multiplier = max(finding.context_multiplier, 1.3)
                    finding.final_score = min(finding.base_score * finding.context_multiplier, 1.0)

    async def _update_node_risk_scores(self):
        """Push computed risk scores back to graph nodes."""
        # Build a map of resource_id -> highest finding score
        node_max_scores: Dict[str, float] = {}
        
        for finding in self.findings:
            rid = finding.resource_id
            node_max_scores[rid] = max(node_max_scores.get(rid, 0.0), finding.final_score)
        
        # Also factor in chain membership
        for chain in self.chains:
            for finding in chain.findings:
                rid = finding.resource_id
                node_max_scores[rid] = max(node_max_scores.get(rid, 0.0), chain.chain_score)
        
        # Update nodes
        for node_id, score in node_max_scores.items():
            if node_id in self.casg.nodes:
                self.casg.nodes[node_id].risk_score = score

    def get_report(self) -> Dict[str, Any]:
        """Generate full risk report."""
        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for finding in self.findings:
            by_severity[finding.severity].append(finding.to_dict())
        
        overall_score = 0.0
        if self.findings:
            # Weighted by severity
            weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0.5}
            total_weight = sum(weights.get(f.severity, 1) for f in self.findings)
            weighted_sum = sum(f.final_score * weights.get(f.severity, 1) for f in self.findings)
            overall_score = min(weighted_sum / max(total_weight, 1), 1.0)
        
        return {
            "overall_risk_score": round(overall_score, 3),
            "overall_severity": score_to_severity(overall_score),
            "total_findings": len(self.findings),
            "risk_chains_detected": len(self.chains),
            "findings_by_severity": {k: len(v) for k, v in by_severity.items()},
            "all_findings": [f.to_dict() for f in sorted(self.findings, key=lambda x: -x.final_score)],
            "risk_chains": [c.to_dict() for c in self.chains],
            "top_10_findings": [f.to_dict() for f in sorted(
                self.findings, key=lambda x: -x.final_score
            )[:10]],
        }

    def print_summary(self):
        """Print rich summary table."""
        table = Table(title="⚡ Dynamic Risk Analysis Results", style="yellow")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("Example Finding")
        
        colors = {
            "CRITICAL": "red", "HIGH": "orange3",
            "MEDIUM": "yellow", "LOW": "green", "INFO": "white"
        }
        
        by_severity: Dict[str, List] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for f in self.findings:
            if f.severity in by_severity:
                by_severity[f.severity].append(f)
        
        for severity, findings_list in by_severity.items():
            color = colors.get(severity, "white")
            example = findings_list[0].title if findings_list else "-"
            table.add_row(
                f"[{color}]{severity}[/{color}]",
                f"[{color}]{len(findings_list)}[/{color}]",
                example[:50]
            )
        
        console.print(table)
        
        if self.chains:
            console.print(f"\n[bold red]🔗 {len(self.chains)} Risk Chains Detected![/bold red]")
            for chain in self.chains:
                console.print(f"  • [{score_to_severity(chain.chain_score)}] {chain.name}: {chain.chain_score:.0%} risk")
