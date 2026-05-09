"""
Module 12: Extended Attacker Simulation
Extends Module 2 (CloudAttackSurfaceGraph) with:
  - Realistic attacker personas (Nation-State, Ransomware, Insider, Script Kiddie)
  - Full kill-chain simulation per persona
  - Lateral movement graph traversal
  - Data exfiltration path scoring
  - Time-to-compromise estimation
  - Integration with Module 11 attack paths
"""

import asyncio
import json
import os
import random
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import boto3
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

console = Console()


# ──────────────────────────────────────────────
# Attacker Persona Definitions
# ──────────────────────────────────────────────

class AttackerPersona(Enum):
    NATION_STATE    = "Nation-State APT"
    RANSOMWARE      = "Ransomware Group"
    INSIDER         = "Malicious Insider"
    SCRIPT_KIDDIE   = "Script Kiddie"
    SUPPLY_CHAIN    = "Supply Chain Attacker"


PERSONA_PROFILES = {
    AttackerPersona.NATION_STATE: {
        "stealth":       0.95,   # avoids detection
        "persistence":   0.90,
        "lateral_move":  0.85,
        "exfil_score":   0.90,
        "ttc_multiplier": 2.5,   # slower = stealthier
        "priority_targets": ["S3", "IAM", "RDS", "Secrets", "KMS"],
        "techniques": [
            "Spear-phishing credential harvest",
            "Supply chain compromise via Lambda layer",
            "Long-term backdoor IAM user",
            "Data exfiltration via encrypted S3 replication",
            "CloudTrail log suppression",
            "Persistence via SCP bypass",
        ],
        "color": "red",
    },
    AttackerPersona.RANSOMWARE: {
        "stealth":       0.30,
        "persistence":   0.70,
        "lateral_move":  0.75,
        "exfil_score":   0.60,
        "ttc_multiplier": 0.5,   # fast and noisy
        "priority_targets": ["S3", "RDS", "EBS", "EC2"],
        "techniques": [
            "Credential stuffing via exposed access keys",
            "Mass S3 encryption with attacker-controlled KMS",
            "RDS snapshot deletion",
            "EC2 AMI wipe",
            "Ransom note via S3 public ACL",
            "Disable CloudTrail to avoid detection",
        ],
        "color": "bright_red",
    },
    AttackerPersona.INSIDER: {
        "stealth":       0.80,
        "persistence":   0.50,
        "lateral_move":  0.60,
        "exfil_score":   0.85,
        "ttc_multiplier": 1.0,
        "priority_targets": ["S3", "RDS", "Secrets", "IAM"],
        "techniques": [
            "Direct console login with legitimate credentials",
            "Bulk S3 data download via presigned URLs",
            "RDS snapshot export to personal account",
            "IAM access key self-creation",
            "CloudTrail event filter tampering",
        ],
        "color": "yellow",
    },
    AttackerPersona.SCRIPT_KIDDIE: {
        "stealth":       0.10,
        "persistence":   0.20,
        "lateral_move":  0.30,
        "exfil_score":   0.20,
        "ttc_multiplier": 0.3,
        "priority_targets": ["S3", "EC2"],
        "techniques": [
            "Public exploit tool (Pacu, ScoutSuite)",
            "Brute-force console login",
            "Open S3 bucket enumeration",
            "EC2 crypto-mining deployment",
            "Public security group abuse",
        ],
        "color": "cyan",
    },
    AttackerPersona.SUPPLY_CHAIN: {
        "stealth":       0.88,
        "persistence":   0.85,
        "lateral_move":  0.80,
        "exfil_score":   0.75,
        "ttc_multiplier": 3.0,
        "priority_targets": ["Lambda", "ECR", "CodeBuild", "IAM"],
        "techniques": [
            "Malicious Lambda layer injection",
            "Compromised ECR base image",
            "CodeBuild environment variable exfiltration",
            "Dependency confusion via public PyPI/npm",
            "CI/CD pipeline secret theft",
        ],
        "color": "magenta",
    },
}


# ──────────────────────────────────────────────
# Data Models
# ──────────────────────────────────────────────

@dataclass
class KillChainStep:
    phase: str
    technique: str
    target: str
    success_prob: float
    detection_risk: float
    time_minutes: int
    aws_evidence: str = ""


@dataclass
class AttackSimResult:
    persona: str
    kill_chain: list[KillChainStep]
    total_score: float
    time_to_compromise_hours: float
    detection_likelihood: float
    blast_radius: list[str]
    aws_confirmed_vulns: list[str]
    exfil_data_estimate_gb: float
    recommendations: list[str]


# ──────────────────────────────────────────────
# AWS Intelligence Gathering
# ──────────────────────────────────────────────

class AWSIntelligence:
    """Pulls live AWS facts to enrich simulation realism."""

    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self.session = boto3.Session(region_name=region)
        self.findings: dict[str, Any] = {}

    def gather(self) -> dict[str, Any]:
        self._check_iam()
        self._check_s3()
        self._check_ec2()
        self._check_cloudtrail()
        self._check_secrets()
        return self.findings

    def _check_iam(self):
        try:
            iam = self.session.client("iam")
            users = iam.list_users()["Users"]
            no_mfa = []
            for u in users:
                devs = iam.list_mfa_devices(UserName=u["UserName"])["MFADevices"]
                if not devs:
                    no_mfa.append(u["UserName"])
            self.findings["iam_users_no_mfa"] = no_mfa
            self.findings["iam_user_count"] = len(users)
            # Check for admin policies
            admin_users = []
            for u in users:
                pols = iam.list_attached_user_policies(UserName=u["UserName"])["AttachedPolicies"]
                if any(p["PolicyName"] == "AdministratorAccess" for p in pols):
                    admin_users.append(u["UserName"])
            self.findings["iam_admin_users"] = admin_users
        except Exception as e:
            self.findings["iam_error"] = str(e)

    def _check_s3(self):
        try:
            s3 = self.session.client("s3")
            buckets = s3.list_buckets()["Buckets"]
            public_buckets = []
            for b in buckets:
                try:
                    acl = s3.get_bucket_acl(Bucket=b["Name"])
                    for grant in acl["Grants"]:
                        if "AllUsers" in grant.get("Grantee", {}).get("URI", ""):
                            public_buckets.append(b["Name"])
                            break
                except Exception:
                    pass
            self.findings["s3_bucket_count"] = len(buckets)
            self.findings["s3_public_buckets"] = public_buckets
        except Exception as e:
            self.findings["s3_error"] = str(e)

    def _check_ec2(self):
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            open_sgs = []
            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    for cidr in perm.get("IpRanges", []):
                        if cidr.get("CidrIp") == "0.0.0.0/0":
                            open_sgs.append(sg["GroupName"])
                            break
            self.findings["ec2_open_security_groups"] = list(set(open_sgs))
            instances = ec2.describe_instances()
            running = sum(
                1 for r in instances["Reservations"]
                for i in r["Instances"]
                if i["State"]["Name"] == "running"
            )
            self.findings["ec2_running_instances"] = running
        except Exception as e:
            self.findings["ec2_error"] = str(e)

    def _check_cloudtrail(self):
        try:
            ct = self.session.client("cloudtrail", region_name=self.region)
            trails = ct.describe_trails()["trailList"]
            logging_disabled = []
            for t in trails:
                status = ct.get_trail_status(Name=t["TrailARN"])
                if not status.get("IsLogging"):
                    logging_disabled.append(t["Name"])
            self.findings["cloudtrail_trails"] = len(trails)
            self.findings["cloudtrail_disabled"] = logging_disabled
        except Exception as e:
            self.findings["cloudtrail_error"] = str(e)

    def _check_secrets(self):
        try:
            sm = self.session.client("secretsmanager", region_name=self.region)
            secrets = sm.list_secrets()["SecretList"]
            self.findings["secrets_count"] = len(secrets)
            self.findings["secrets_names"] = [s["Name"] for s in secrets[:10]]
        except Exception as e:
            self.findings["secrets_error"] = str(e)


# ──────────────────────────────────────────────
# Kill Chain Builder
# ──────────────────────────────────────────────

KILL_CHAIN_TEMPLATES = {
    AttackerPersona.NATION_STATE: [
        ("Reconnaissance",      "OSINT + LinkedIn scraping for AWS account IDs",    "External",  0.99, 0.02, 120),
        ("Initial Access",      "Spear-phishing → stolen console credentials",       "IAM User",  0.75, 0.15, 240),
        ("Execution",           "Lambda function deployment with reverse shell",      "Lambda",    0.70, 0.20, 60),
        ("Persistence",         "Hidden IAM backdoor user + long-lived access key",  "IAM",       0.85, 0.10, 30),
        ("Defense Evasion",     "CloudTrail log deletion + GuardDuty suppression",   "CloudTrail",0.80, 0.05, 45),
        ("Credential Access",   "Secrets Manager bulk dump",                         "Secrets",   0.90, 0.08, 20),
        ("Lateral Movement",    "Cross-account role assumption via weak trust",      "IAM Role",  0.65, 0.12, 90),
        ("Collection",          "S3 bucket enumeration + selective data staging",    "S3",        0.95, 0.05, 180),
        ("Exfiltration",        "Encrypted S3 replication to attacker account",      "S3",        0.88, 0.03, 300),
        ("Impact",              "Persistent access maintained; data sold/exploited", "All",       1.00, 0.00, 0),
    ],
    AttackerPersona.RANSOMWARE: [
        ("Reconnaissance",   "Shodan scan for exposed AWS endpoints",             "External",  0.99, 0.05, 15),
        ("Initial Access",   "Credential stuffing via leaked access keys (GitHub)","IAM User",  0.80, 0.40, 10),
        ("Execution",        "Pacu framework automated exploitation",              "EC2/Lambda",0.75, 0.60, 20),
        ("Persistence",      "Admin IAM user created for ransom negotiation",      "IAM",       0.70, 0.50, 5),
        ("Defense Evasion",  "CloudTrail disabled + GuardDuty detector deleted",   "CloudTrail",0.65, 0.70, 5),
        ("Impact",           "S3 mass re-encryption + RDS snapshot deletion",      "S3/RDS",    0.85, 0.95, 30),
        ("Impact",           "Ransom note uploaded to public S3 bucket",           "S3",        1.00, 1.00, 5),
    ],
    AttackerPersona.INSIDER: [
        ("Reconnaissance",      "Internal Confluence/Slack data mining",              "Internal",  0.99, 0.05, 480),
        ("Initial Access",      "Console login with own valid credentials",           "Console",   1.00, 0.02, 5),
        ("Collection",          "Bulk S3 download via AWS CLI with own permissions",  "S3",        0.95, 0.20, 60),
        ("Credential Access",   "Self-create additional IAM access key",              "IAM",       0.90, 0.25, 5),
        ("Exfiltration",        "RDS snapshot exported to personal AWS account",      "RDS",       0.80, 0.30, 120),
        ("Lateral Movement",    "Assume roles granted by overly permissive policies", "IAM Role",  0.70, 0.20, 30),
        ("Defense Evasion",     "Delete CloudTrail events via console",               "CloudTrail",0.60, 0.40, 10),
    ],
    AttackerPersona.SCRIPT_KIDDIE: [
        ("Reconnaissance",  "ScoutSuite / Pacu auto-scan",                    "External",  0.99, 0.80, 5),
        ("Initial Access",  "Open S3 bucket access / brute force login",      "S3/Console",0.50, 0.90, 10),
        ("Execution",       "EC2 crypto-miner deployment (UserData script)",  "EC2",       0.60, 0.95, 15),
        ("Impact",          "Resource abuse for crypto mining",               "EC2",       0.70, 0.99, 0),
    ],
    AttackerPersona.SUPPLY_CHAIN: [
        ("Reconnaissance",    "Open-source dependency graph analysis",             "External",  0.99, 0.01, 240),
        ("Initial Access",    "Malicious Lambda layer published to public registry","Lambda",    0.70, 0.05, 480),
        ("Execution",         "Lambda env var exfiltration on next invocation",    "Lambda",    0.85, 0.10, 0),
        ("Persistence",       "Backdoor baked into ECR base image",               "ECR",       0.80, 0.08, 120),
        ("Credential Access", "CI/CD env secrets exfiltrated via CodeBuild logs", "CodeBuild", 0.75, 0.12, 60),
        ("Lateral Movement",  "Use stolen creds to pivot to production account",  "IAM",       0.65, 0.15, 90),
        ("Collection",        "Bulk secret export from Secrets Manager",          "Secrets",   0.88, 0.10, 30),
        ("Exfiltration",      "Data exfil via DNS tunneling from Lambda",         "Lambda",    0.72, 0.05, 180),
    ],
}


def build_kill_chain(persona: AttackerPersona, intel: dict) -> list[KillChainStep]:
    steps = []
    profile = PERSONA_PROFILES[persona]
    templates = KILL_CHAIN_TEMPLATES.get(persona, [])

    for phase, technique, target, base_prob, detect_risk, time_min in templates:
        # Adjust probabilities based on live AWS findings
        adj_prob = base_prob
        adj_detect = detect_risk

        if target == "IAM" and intel.get("iam_users_no_mfa"):
            adj_prob = min(1.0, adj_prob + 0.10)
        if target == "S3" and intel.get("s3_public_buckets"):
            adj_prob = min(1.0, adj_prob + 0.15)
        if target == "CloudTrail" and intel.get("cloudtrail_disabled"):
            adj_detect = max(0.01, adj_detect - 0.20)
        if target == "EC2" and intel.get("ec2_open_security_groups"):
            adj_prob = min(1.0, adj_prob + 0.10)

        # Stealth modifier
        adj_detect = adj_detect * (1.0 - profile["stealth"] * 0.3)

        # Build evidence string from intel
        evidence = ""
        if "iam_users_no_mfa" in intel and target in ("IAM", "IAM User", "IAM Role"):
            evidence = f"No-MFA users: {', '.join(intel['iam_users_no_mfa'][:3])}"
        elif "s3_public_buckets" in intel and target == "S3":
            pubs = intel.get("s3_public_buckets", [])
            evidence = f"Public buckets: {', '.join(pubs[:2])}" if pubs else "No public buckets found"
        elif "ec2_open_security_groups" in intel and "EC2" in target:
            sgs = intel.get("ec2_open_security_groups", [])
            evidence = f"Open SGs: {', '.join(sgs[:2])}" if sgs else ""

        steps.append(KillChainStep(
            phase=phase,
            technique=technique,
            target=target,
            success_prob=round(adj_prob, 2),
            detection_risk=round(adj_detect, 2),
            time_minutes=time_min,
            aws_evidence=evidence,
        ))
    return steps


# ──────────────────────────────────────────────
# Scoring Engine
# ──────────────────────────────────────────────

def score_simulation(
    persona: AttackerPersona,
    kill_chain: list[KillChainStep],
    intel: dict,
    profile: dict,
) -> AttackSimResult:
    total_time = sum(s.time_minutes for s in kill_chain)
    ttc_hours = (total_time * profile["ttc_multiplier"]) / 60.0

    # Detection likelihood: highest detection risk step drives overall
    max_detect = max((s.detection_risk for s in kill_chain), default=0.0)
    avg_detect = sum(s.detection_risk for s in kill_chain) / max(len(kill_chain), 1)
    detection_likelihood = round((max_detect * 0.4 + avg_detect * 0.6), 2)

    # Overall success score
    total_score = round(
        sum(s.success_prob for s in kill_chain) / max(len(kill_chain), 1) *
        profile["exfil_score"],
        2
    )

    # Blast radius — what services are impacted
    blast = list({s.target for s in kill_chain if s.target not in ("External", "Internal", "Console", "All")})

    # AWS confirmed vulns (from intel)
    confirmed = []
    if intel.get("iam_users_no_mfa"):
        confirmed.append(f"MFA not enabled: {', '.join(intel['iam_users_no_mfa'])}")
    if intel.get("s3_public_buckets"):
        confirmed.append(f"Public S3 buckets: {', '.join(intel['s3_public_buckets'])}")
    if intel.get("ec2_open_security_groups"):
        confirmed.append(f"Open security groups (0.0.0.0/0): {', '.join(intel['ec2_open_security_groups'])}")
    if intel.get("cloudtrail_disabled"):
        confirmed.append(f"CloudTrail logging disabled: {', '.join(intel['cloudtrail_disabled'])}")
    if intel.get("iam_admin_users"):
        confirmed.append(f"Direct admin policy on users: {', '.join(intel['iam_admin_users'])}")

    # Exfil estimate (rough heuristic)
    exfil_gb = round(
        (intel.get("s3_bucket_count", 0) * 0.5 +
         intel.get("secrets_count", 0) * 0.001) *
        profile["exfil_score"],
        2
    )

    # Recommendations
    recs = []
    if intel.get("iam_users_no_mfa"):
        recs.append("Enable MFA for all IAM users immediately (CRITICAL)")
    if intel.get("s3_public_buckets"):
        recs.append("Block public S3 access at account level via S3 Block Public Access")
    if intel.get("ec2_open_security_groups"):
        recs.append("Restrict security groups — remove 0.0.0.0/0 ingress rules")
    if intel.get("cloudtrail_disabled"):
        recs.append("Re-enable CloudTrail and enable log file integrity validation")
    if intel.get("iam_admin_users"):
        recs.append("Remove AdministratorAccess from individual users; use roles with least privilege")
    if persona == AttackerPersona.NATION_STATE:
        recs.append("Deploy GuardDuty + Security Hub + AWS Detective for APT detection")
    if persona == AttackerPersona.RANSOMWARE:
        recs.append("Enable S3 Versioning + Object Lock; use AWS Backup for RDS")
    if persona == AttackerPersona.SUPPLY_CHAIN:
        recs.append("Pin Lambda layer versions; enable ECR image scanning; use CodeArtifact")

    return AttackSimResult(
        persona=persona.value,
        kill_chain=kill_chain,
        total_score=total_score,
        time_to_compromise_hours=round(ttc_hours, 1),
        detection_likelihood=detection_likelihood,
        blast_radius=blast,
        aws_confirmed_vulns=confirmed,
        exfil_data_estimate_gb=exfil_gb,
        recommendations=recs,
    )


# ──────────────────────────────────────────────
# Rich Output
# ──────────────────────────────────────────────

def render_kill_chain(result: AttackSimResult, profile: dict):
    persona_color = profile["color"]

    console.print(f"\n[bold {persona_color}]━━━ {result.persona} ━━━[/bold {persona_color}]")

    # Kill chain table
    table = Table(box=box.SIMPLE_HEAVY, show_lines=True)
    table.add_column("Phase",           style="bold white",  width=20)
    table.add_column("Technique",       style="white",       width=38)
    table.add_column("Target",          style="cyan",        width=12)
    table.add_column("Success%",        style="green",       width=9, justify="center")
    table.add_column("Detect Risk",     style="yellow",      width=11, justify="center")
    table.add_column("Time",            style="dim",         width=8, justify="right")
    table.add_column("AWS Evidence",    style="dim cyan",    width=30)

    for step in result.kill_chain:
        success_bar = "█" * int(step.success_prob * 10)
        detect_bar  = "▲" * int(step.detection_risk * 10)
        table.add_row(
            step.phase,
            step.technique,
            step.target,
            f"{int(step.success_prob * 100)}% {success_bar}",
            f"{int(step.detection_risk * 100)}% {detect_bar}",
            f"{step.time_minutes}m",
            step.aws_evidence or "—",
        )
    console.print(table)

    # Summary panel
    score_color = "red" if result.total_score >= 0.7 else "yellow" if result.total_score >= 0.4 else "green"
    lines = [
        f"  [bold]Exploit Score:[/bold]          [{score_color}]{result.total_score}[/{score_color}]",
        f"  [bold]Time to Compromise:[/bold]     {result.time_to_compromise_hours}h",
        f"  [bold]Detection Likelihood:[/bold]   {int(result.detection_likelihood * 100)}%",
        f"  [bold]Blast Radius:[/bold]           {', '.join(result.blast_radius)}",
        f"  [bold]Exfil Estimate:[/bold]         {result.exfil_data_estimate_gb} GB",
    ]
    if result.aws_confirmed_vulns:
        lines.append("\n  [bold red]AWS-Confirmed Vulnerabilities:[/bold red]")
        for v in result.aws_confirmed_vulns:
            lines.append(f"    [red]✗[/red] {v}")
    if result.recommendations:
        lines.append("\n  [bold green]Recommendations:[/bold green]")
        for r in result.recommendations:
            lines.append(f"    [green]→[/green] {r}")

    console.print(Panel("\n".join(lines), title=f"[bold]Summary — {result.persona}[/bold]", border_style=persona_color))


# ──────────────────────────────────────────────
# Main Entry Point
# ──────────────────────────────────────────────

async def run_extended_attack_simulation(
    account_id: str = "",
    region: str = "us-east-1",
    personas: list[AttackerPersona] | None = None,
    export_json: bool = True,
) -> list[AttackSimResult]:
    """
    Run all (or selected) attacker persona simulations against the live AWS account.
    Returns list of AttackSimResult for downstream reporting.
    """
    if personas is None:
        personas = list(AttackerPersona)

    console.rule("[bold blue]Module 12: Extended Attacker Simulation[/bold blue]")

    # Gather live AWS intel
    console.print("\n[cyan]● Gathering live AWS intelligence...[/cyan]")
    intel_engine = AWSIntelligence(region=region)
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as prog:
        t = prog.add_task("Scanning IAM, S3, EC2, CloudTrail, Secrets...", total=None)
        intel = intel_engine.gather()
        prog.update(t, completed=True)

    console.print(f"  [green]✓[/green] IAM users: {intel.get('iam_user_count', '?')}  "
                  f"No-MFA: {len(intel.get('iam_users_no_mfa', []))}  "
                  f"S3 buckets: {intel.get('s3_bucket_count', '?')}  "
                  f"Secrets: {intel.get('secrets_count', '?')}")

    results: list[AttackSimResult] = []

    for persona in personas:
        profile = PERSONA_PROFILES[persona]
        console.print(f"\n[bold {profile['color']}]▶ Simulating: {persona.value}[/bold {profile['color']}]")

        kill_chain = build_kill_chain(persona, intel)
        result = score_simulation(persona, kill_chain, intel, profile)
        render_kill_chain(result, profile)
        results.append(result)

    # Overall comparison table
    console.rule("[bold]Cross-Persona Threat Comparison[/bold]")
    cmp_table = Table(box=box.DOUBLE_EDGE)
    cmp_table.add_column("Persona",          style="bold white", width=22)
    cmp_table.add_column("Exploit Score",    justify="center",   width=14)
    cmp_table.add_column("Time-to-Pwn",      justify="center",   width=13)
    cmp_table.add_column("Detection Risk",   justify="center",   width=15)
    cmp_table.add_column("Blast Radius",     width=30)
    cmp_table.add_column("Confirmed Vulns",  justify="center",   width=14)

    for r in sorted(results, key=lambda x: x.total_score, reverse=True):
        score_color = "red" if r.total_score >= 0.7 else "yellow" if r.total_score >= 0.4 else "green"
        cmp_table.add_row(
            r.persona,
            f"[{score_color}]{r.total_score}[/{score_color}]",
            f"{r.time_to_compromise_hours}h",
            f"{int(r.detection_likelihood * 100)}%",
            ", ".join(r.blast_radius[:4]),
            str(len(r.aws_confirmed_vulns)),
        )
    console.print(cmp_table)

    # Export
    if export_json:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        fname = f"attack_sim_extended_{ts}.json"
        payload = {
            "module": "Module 12 — Extended Attacker Simulation",
            "account_id": account_id,
            "region": region,
            "timestamp": ts,
            "aws_intel": {k: v for k, v in intel.items() if "error" not in k},
            "simulations": [
                {
                    "persona": r.persona,
                    "exploit_score": r.total_score,
                    "time_to_compromise_hours": r.time_to_compromise_hours,
                    "detection_likelihood": r.detection_likelihood,
                    "blast_radius": r.blast_radius,
                    "aws_confirmed_vulns": r.aws_confirmed_vulns,
                    "exfil_estimate_gb": r.exfil_data_estimate_gb,
                    "recommendations": r.recommendations,
                    "kill_chain": [asdict(s) for s in r.kill_chain],
                }
                for r in results
            ],
        }
        with open(fname, "w") as f:
            json.dump(payload, f, indent=2)
        console.print(f"\n[green]✓ Report exported: {fname}[/green]")

    return results
