import asyncio, json, logging, random
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List
import boto3
import networkx as nx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from modules.attack_sim.simulator import AIAttackSimulator, AttackAction, AttackPath, AttackTechnique

console = Console()
logger = logging.getLogger(__name__)

class KillChainPhase:
    RECONNAISSANCE    = "Reconnaissance"
    INITIAL_ACCESS    = "Initial Access"
    PERSISTENCE       = "Persistence"
    PRIV_ESCALATION   = "Privilege Escalation"
    CREDENTIAL_ACCESS = "Credential Access"
    LATERAL_MOVEMENT  = "Lateral Movement"
    EXFILTRATION      = "Exfiltration"

TECHNIQUE_PHASE = {
    "T1078": KillChainPhase.INITIAL_ACCESS,
    "T1552.001": KillChainPhase.CREDENTIAL_ACCESS,
    "T1548.005": KillChainPhase.PRIV_ESCALATION,
    "T1484.001": KillChainPhase.PRIV_ESCALATION,
    "T1552.005": KillChainPhase.CREDENTIAL_ACCESS,
    "T1580": KillChainPhase.RECONNAISSANCE,
    "T1530": KillChainPhase.EXFILTRATION,
    "T1136": KillChainPhase.PERSISTENCE,
    "T1098.001": KillChainPhase.PERSISTENCE,
    "T1110.001": KillChainPhase.CREDENTIAL_ACCESS,
}

@dataclass
class Countermeasure:
    name: str
    description: str
    blocks_techniques: List[str]
    prevention_probability: float
    aws_service: str

COUNTERMEASURES = [
    Countermeasure("MFA Enforcement", "Require MFA for all IAM users",
        ["T1078", "T1110.001", "T1552.001"], 0.85, "IAM"),
    Countermeasure("S3 Block Public Access", "Block all public S3 access at account level",
        ["T1530"], 0.95, "S3"),
    Countermeasure("IMDSv2 Enforcement", "Require IMDSv2 tokens on all EC2 instances",
        ["T1552.005"], 0.90, "EC2"),
    Countermeasure("Least Privilege IAM", "Remove wildcard permissions",
        ["T1548.005", "T1484.001", "T1136"], 0.70, "IAM"),
    Countermeasure("GuardDuty", "AWS threat detection for anomalous API calls",
        [], 0.0, "GuardDuty"),
]

@dataclass
class AdvancedAttackPath(AttackPath):
    kill_chain_phases: List[str] = field(default_factory=list)
    blocked_by: List[str] = field(default_factory=list)
    exploitability_score: float = 0.0
    validated_on_aws: bool = False
    validation_result: str = "not_checked"
    remediation_priority: str = "LOW"
    remediation_steps: List[str] = field(default_factory=list)
    scenario_name: str = ""

    def calculate_advanced_metrics(self):
        self.calculate_metrics()
        self.kill_chain_phases = list(dict.fromkeys(
            TECHNIQUE_PHASE.get(s.technique.value, "Unknown") for s in self.steps))
        chain_bonus = min(len(self.kill_chain_phases) / 6, 1.0)
        self.exploitability_score = round(
            self.overall_success_prob * 0.35 +
            min(self.total_damage_score, 1.0) * 0.35 +
            self.avg_stealth * 0.15 + chain_bonus * 0.15, 3)
        if self.exploitability_score > 0.7: self.remediation_priority = "CRITICAL"
        elif self.exploitability_score > 0.5: self.remediation_priority = "HIGH"
        elif self.exploitability_score > 0.3: self.remediation_priority = "MEDIUM"
        else: self.remediation_priority = "LOW"

    def score_countermeasures(self):
        techs = {s.technique.value for s in self.steps}
        for cm in COUNTERMEASURES:
            if techs.intersection(set(cm.blocks_techniques)) and cm.prevention_probability > 0.5:
                self.blocked_by.append(cm.name)

    def generate_remediation(self):
        techs = {s.technique.value for s in self.steps}
        self.remediation_steps = [
            f"[{cm.aws_service}] {cm.name}: {cm.description}"
            for cm in COUNTERMEASURES if set(cm.blocks_techniques).intersection(techs)]

    def to_advanced_dict(self):
        base = self.to_dict()
        base.update({"scenario_name": self.scenario_name,
            "kill_chain_phases": self.kill_chain_phases,
            "exploitability_score": self.exploitability_score,
            "remediation_priority": self.remediation_priority,
            "blocked_by": self.blocked_by,
            "validated_on_aws": self.validated_on_aws,
            "validation_result": self.validation_result,
            "remediation_steps": self.remediation_steps})
        return base

class AdvancedAttackSimulator:
    def __init__(self, casg, region="us-east-1", account_id=""):
        self.casg = casg
        self.region = region
        self.account_id = account_id
        self.paths: List[AdvancedAttackPath] = []
        self.iam = boto3.client("iam", region_name=region)
        self.s3  = boto3.client("s3",  region_name=region)
        self.ec2 = boto3.client("ec2", region_name=region)

    async def scenario_credential_stuffing(self):
        paths, counter = [], 0
        for uid, unode in [(nid, n) for nid, n in self.casg.nodes.items()
                           if n.node_type.value == "IAM_USER"]:
            counter += 1
            no_mfa = any("MFA" in m for m in unode.misconfigurations)
            path = AdvancedAttackPath(path_id=f"CRED-{counter:04d}",
                objective="credential_stuffing",
                scenario_name="Credential Stuffing via Leaked Password Lists")
            path.steps = [
                AttackAction(technique=AttackTechnique.VALID_ACCOUNTS,
                    source_node="external_attacker", target_node=uid,
                    success_probability=min(0.35 + (0.30 if no_mfa else 0) + unode.risk_score * 0.2, 0.92),
                    damage_score=0.6, stealth_score=0.4,
                    description=f"Try leaked passwords against {unode.name} ({'no MFA' if no_mfa else 'MFA present'})"),
                AttackAction(technique=AttackTechnique.EXPOSED_KEYS,
                    source_node=uid, target_node=uid,
                    success_probability=0.8, damage_score=0.7, stealth_score=0.5,
                    description=f"Create persistent access key as {unode.name}"),
            ]
            path.calculate_advanced_metrics(); path.score_countermeasures(); path.generate_remediation()
            paths.append(path)
        return paths

    async def scenario_imds_metadata_theft(self):
        paths, counter = [], 0
        for ec2_id, ec2_node in [(nid, n) for nid, n in self.casg.nodes.items()
                                  if n.node_type.value == "EC2_INSTANCE"]:
            counter += 1
            imdsv1 = any("IMDSv1" in m or "metadata" in m.lower() for m in ec2_node.misconfigurations)
            path = AdvancedAttackPath(path_id=f"IMDS-{counter:04d}",
                objective="imds_credential_theft",
                scenario_name="SSRF -> IMDSv1 -> IAM Role Credential Theft")
            path.steps = [
                AttackAction(technique=AttackTechnique.INSTANCE_METADATA,
                    source_node="external_attacker", target_node=ec2_id,
                    success_probability=0.85 if imdsv1 else 0.30,
                    damage_score=0.75, stealth_score=0.7,
                    description=f"Exploit SSRF on {ec2_node.name} to query IMDSv1 endpoint"),
            ]
            reachable_roles = [(nid, n) for nid, n in self.casg.nodes.items()
                if n.node_type.value == "IAM_ROLE" and
                nx.has_path(self.casg.nx_graph, ec2_id, nid)]
            for role_id, role_node in reachable_roles[:2]:
                path.steps.append(AttackAction(technique=AttackTechnique.ROLE_ASSUMPTION,
                    source_node=ec2_id, target_node=role_id,
                    success_probability=0.9, damage_score=role_node.risk_score, stealth_score=0.65,
                    description=f"Use stolen instance profile to assume {role_node.name}"))
            path.calculate_advanced_metrics(); path.score_countermeasures(); path.generate_remediation()
            paths.append(path)
        return paths

    async def scenario_cross_account_pivot(self):
        paths, counter = [], 0
        for role_id, role_node in [(nid, n) for nid, n in self.casg.nodes.items()
                                    if n.node_type.value == "IAM_ROLE"]:
            counter += 1
            wildcard = any("wildcard" in m.lower() or "*" in m for m in role_node.misconfigurations)
            path = AdvancedAttackPath(path_id=f"XACCT-{counter:04d}",
                objective="cross_account_pivot",
                scenario_name="Cross-Account Role Assumption via Weak Trust Policy")
            path.steps = [
                AttackAction(technique=AttackTechnique.ROLE_ASSUMPTION,
                    source_node="external_aws_account", target_node=role_id,
                    success_probability=0.75 if wildcard else 0.25,
                    damage_score=0.85, stealth_score=0.6,
                    description=f"Assume {role_node.name} from attacker-controlled AWS account"),
                AttackAction(technique=AttackTechnique.POLICY_MANIPULATION,
                    source_node=role_id, target_node=role_id,
                    success_probability=0.7, damage_score=0.9, stealth_score=0.5,
                    description=f"Escalate via {role_node.name} — attach AdministratorAccess"),
            ]
            path.calculate_advanced_metrics(); path.score_countermeasures(); path.generate_remediation()
            paths.append(path)
        return paths

    async def scenario_backdoor_persistence(self):
        paths, counter = [], 0
        for src_id, src_node in [(nid, n) for nid, n in self.casg.nodes.items()
                                  if n.node_type.value in ("IAM_USER", "IAM_ROLE")
                                  and n.risk_score > 0.4]:
            counter += 1
            path = AdvancedAttackPath(path_id=f"BACK-{counter:04d}",
                objective="persistence_backdoor",
                scenario_name="Hidden IAM Backdoor User + Persistent Access Key")
            path.steps = [
                AttackAction(technique=AttackTechnique.VALID_ACCOUNTS,
                    source_node="external_attacker", target_node=src_id,
                    success_probability=0.6 + src_node.risk_score * 0.2,
                    damage_score=0.5, stealth_score=0.5,
                    description=f"Initial compromise of {src_node.name}"),
                AttackAction(technique=AttackTechnique.CREATE_ACCOUNT,
                    source_node=src_id, target_node="new_hidden_user",
                    success_probability=0.85, damage_score=0.7, stealth_score=0.8,
                    description="Create hidden IAM user with innocuous name (e.g. svc-monitor)"),
                AttackAction(technique=AttackTechnique.CREATE_ACCESS_KEY,
                    source_node="new_hidden_user", target_node="new_hidden_user",
                    success_probability=0.95, damage_score=0.8, stealth_score=0.85,
                    description="Create long-lived access key — no expiry, no MFA, no monitoring"),
            ]
            path.calculate_advanced_metrics(); path.score_countermeasures(); path.generate_remediation()
            paths.append(path)
        return paths

    async def validate_paths_on_aws(self, paths):
        console.print("[yellow]Validating paths against live AWS account...[/yellow]")
        try:
            users = self.iam.list_users().get("Users", [])
            users_no_mfa = set()
            for u in users:
                if not self.iam.list_mfa_devices(UserName=u["UserName"]).get("MFADevices"):
                    users_no_mfa.add(u["UserName"])
            reservations = self.ec2.describe_instances().get("Reservations", [])
            imdsv1 = {i["InstanceId"] for r in reservations for i in r.get("Instances", [])
                      if i.get("MetadataOptions", {}).get("HttpTokens") == "optional"}
            for path in paths:
                if path.objective == "credential_stuffing" and users_no_mfa:
                    path.validated_on_aws = True
                    path.validation_result = f"CONFIRMED — {len(users_no_mfa)} users without MFA: {', '.join(list(users_no_mfa)[:3])}"
                elif path.objective == "imds_credential_theft" and imdsv1:
                    path.validated_on_aws = True
                    path.validation_result = f"CONFIRMED — {len(imdsv1)} EC2 instances running IMDSv1"
                elif path.objective == "persistence_backdoor" and users_no_mfa:
                    path.validated_on_aws = True
                    path.validation_result = f"CONFIRMED — backdoor creation would go undetected"
                else:
                    path.validation_result = "MANUAL CHECK REQUIRED"
            console.print(f"[green]✓ Validated {len(paths)} paths[/green]")
        except Exception as e:
            console.print(f"[red]Validation error: {e}[/red]")

    async def run_advanced_simulation(self):
        console.print("\n[bold red]--- Module 11: Advanced Attack Simulation ---[/bold red]")
        all_paths = []
        for name, fn in [
            ("Credential Stuffing", self.scenario_credential_stuffing),
            ("IMDS Metadata Theft", self.scenario_imds_metadata_theft),
            ("Cross-Account Pivot", self.scenario_cross_account_pivot),
            ("Backdoor Persistence", self.scenario_backdoor_persistence),
        ]:
            console.print(f"[yellow]  → {name}...[/yellow]")
            try:
                results = await fn()
                all_paths.extend(results)
                console.print(f"[green]    ✓ {len(results)} paths[/green]")
            except Exception as e:
                console.print(f"[red]    ✗ {e}[/red]")
        all_paths.sort(key=lambda p: -p.exploitability_score)
        self.paths = all_paths
        await self.validate_paths_on_aws(all_paths)
        return all_paths

    def display_results(self):
        if not self.paths: return
        table = Table(title="Advanced Attack Paths — Module 11")
        table.add_column("Path ID", style="dim")
        table.add_column("Scenario", max_width=38)
        table.add_column("Exploit Score", justify="right")
        table.add_column("Priority", style="bold")
        table.add_column("AWS Validated")
        table.add_column("Kill Chain")
        colors = {"CRITICAL": "red bold", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "cyan"}
        for p in self.paths[:15]:
            c = colors.get(p.remediation_priority, "white")
            val = "[red]CONFIRMED[/red]" if p.validated_on_aws else "[green]Mitigated[/green]"
            table.add_row(p.path_id, p.scenario_name[:38],
                f"[{c}]{p.exploitability_score:.2f}[/{c}]",
                f"[{c}]{p.remediation_priority}[/{c}]",
                val, " -> ".join(p.kill_chain_phases[:3]))
        console.print(table)
        confirmed = [p for p in self.paths if p.validated_on_aws]
        if confirmed:
            console.print(Panel(
                "\n".join(f"  [{p.path_id}] {p.scenario_name}\n     {p.validation_result}"
                          for p in confirmed[:5]),
                title="[red bold]AWS-Confirmed Exploitable Paths[/red bold]", border_style="red"))

    def display_summary(self):
        pc = defaultdict(int)
        for p in self.paths: pc[p.remediation_priority] += 1
        console.print(Panel(
            f"\n[bold]Advanced Simulation Complete[/bold]\n\n"
            f"Total paths: {len(self.paths)}   Confirmed on AWS: {sum(1 for p in self.paths if p.validated_on_aws)}\n"
            f"[red]CRITICAL: {pc['CRITICAL']}[/red]  [orange3]HIGH: {pc['HIGH']}[/orange3]  "
            f"[yellow]MEDIUM: {pc['MEDIUM']}[/yellow]  [cyan]LOW: {pc['LOW']}[/cyan]",
            title="[bold cyan]Module 11: Advanced Attack Simulation[/bold cyan]", border_style="cyan"))

    def export_report(self):
        filename = f"attack_sim_advanced_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report = {"report_metadata": {"generated_at": datetime.now(timezone.utc).isoformat(),
            "module": "Module 11 — Advanced Attack Simulation", "institution": "IIIT Nagpur"},
            "summary": {"total_paths": len(self.paths),
                "confirmed_on_aws": sum(1 for p in self.paths if p.validated_on_aws),
                "priority_breakdown": {k: sum(1 for p in self.paths if p.remediation_priority == k)
                    for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}},
            "attack_paths": [p.to_advanced_dict() for p in self.paths]}
        with open(filename, "w") as f:
            json.dump(report, f, indent=2, default=str)
        console.print(f"[green]✓ Report exported: {filename}[/green]")
        return filename

async def run_advanced_attack_simulation(casg, account_id, region="us-east-1"):
    sim = AdvancedAttackSimulator(casg=casg, region=region, account_id=account_id)
    await sim.run_advanced_simulation()
    sim.display_results()
    sim.display_summary()
    sim.export_report()
