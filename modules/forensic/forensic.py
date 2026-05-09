import boto3, json, logging, asyncio
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
logger = logging.getLogger(__name__)

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"

SEVERITY_COLOR = {
    SEVERITY_CRITICAL: "red bold",
    SEVERITY_HIGH:     "orange3",
    SEVERITY_MEDIUM:   "yellow",
    SEVERITY_LOW:      "cyan",
}

SUSPICIOUS_ACTIONS = {
    "AttachUserPolicy":              (SEVERITY_CRITICAL, "Privilege escalation — policy attached to user"),
    "AttachRolePolicy":              (SEVERITY_CRITICAL, "Privilege escalation — policy attached to role"),
    "PutUserPolicy":                 (SEVERITY_CRITICAL, "Inline policy added to user"),
    "CreateLoginProfile":            (SEVERITY_HIGH,     "Console access created for IAM user"),
    "UpdateLoginProfile":            (SEVERITY_HIGH,     "Console password changed"),
    "CreateAccessKey":               (SEVERITY_CRITICAL, "New access key created"),
    "UpdateAccessKey":               (SEVERITY_MEDIUM,   "Access key updated"),
    "CreateUser":                    (SEVERITY_HIGH,     "New IAM user created"),
    "CreateRole":                    (SEVERITY_HIGH,     "New IAM role created"),
    "AddUserToGroup":                (SEVERITY_HIGH,     "User added to IAM group"),
    "DeactivateMFADevice":           (SEVERITY_CRITICAL, "MFA deactivated — account takeover risk"),
    "ListBuckets":                   (SEVERITY_LOW,      "S3 bucket enumeration"),
    "ListUsers":                     (SEVERITY_LOW,      "IAM user enumeration"),
    "ListRoles":                     (SEVERITY_LOW,      "IAM role enumeration"),
    "GetAccountSummary":             (SEVERITY_LOW,      "Account summary pulled"),
    "DescribeInstances":             (SEVERITY_LOW,      "EC2 instance enumeration"),
    "ListFunctions":                 (SEVERITY_LOW,      "Lambda function enumeration"),
    "ListSecrets":                   (SEVERITY_MEDIUM,   "Secrets Manager enumeration"),
    "GetSecretValue":                (SEVERITY_HIGH,     "Secret value accessed"),
    "GetObject":                     (SEVERITY_MEDIUM,   "S3 object downloaded"),
    "PutBucketPolicy":               (SEVERITY_HIGH,     "S3 bucket policy modified"),
    "PutPublicAccessBlock":          (SEVERITY_HIGH,     "S3 public access block modified"),
    "RunInstances":                  (SEVERITY_HIGH,     "EC2 instance launched"),
    "TerminateInstances":            (SEVERITY_HIGH,     "EC2 instance terminated"),
    "AuthorizeSecurityGroupIngress": (SEVERITY_HIGH,     "Inbound firewall rule added"),
    "DeleteTrail":                   (SEVERITY_CRITICAL, "CloudTrail trail deleted — evidence tampering"),
    "StopLogging":                   (SEVERITY_CRITICAL, "CloudTrail logging stopped"),
    "DeleteFlowLogs":                (SEVERITY_HIGH,     "VPC flow logs deleted"),
    "AssumeRole":                    (SEVERITY_MEDIUM,   "Role assumed"),
    "GetSessionToken":               (SEVERITY_MEDIUM,   "Temporary session token requested"),
    "GetFederationToken":            (SEVERITY_HIGH,     "Federation token requested"),
    "RequestSpotInstances":          (SEVERITY_MEDIUM,   "Spot instances requested — possible crypto mining"),
}

RECON_THRESHOLD = 15

@dataclass
class ForensicEvent:
    timestamp: str
    event_name: str
    source_ip: str
    user_agent: str
    user_identity: str
    user_type: str
    region: str
    severity: str
    description: str
    error_code: str = ""
    resources: List[str] = field(default_factory=list)

    def to_dict(self):
        return {"timestamp": self.timestamp, "event": self.event_name,
                "source_ip": self.source_ip, "user_identity": self.user_identity,
                "severity": self.severity, "description": self.description,
                "error_code": self.error_code, "resources": self.resources}

@dataclass
class ThreatSummary:
    ip_address: str
    event_count: int
    unique_actions: int
    highest_severity: str
    first_seen: str
    last_seen: str
    identities_used: List[str]
    top_actions: List[str]

class ForensicInvestigationEngine:
    def __init__(self, region="us-east-1", account_id=""):
        self.region = region
        self.account_id = account_id
        self.events: List[ForensicEvent] = []
        self.raw_count = 0
        self.cloudtrail = boto3.client("cloudtrail", region_name=region)

    async def collect_cloudtrail_events(self, hours=72):
        console.print(f"[yellow]Pulling CloudTrail events for last {hours}h...[/yellow]")
        start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        try:
            paginator = self.cloudtrail.get_paginator("lookup_events")
            for page in paginator.paginate(StartTime=start_time,
                                           PaginationConfig={"MaxItems": 2000, "PageSize": 50}):
                for raw in page.get("Events", []):
                    self.raw_count += 1
                    event = self._parse_event(raw)
                    if event:
                        self.events.append(event)
            console.print(f"[green]✓ Scanned {self.raw_count} events, {len(self.events)} flagged[/green]")
        except Exception as e:
            console.print(f"[red]CloudTrail error: {e}[/red]")

    def _parse_event(self, raw):
        try:
            event_name = raw.get("EventName", "")
            if event_name not in SUSPICIOUS_ACTIONS:
                return None
            detail = json.loads(raw.get("CloudTrailEvent", "{}"))
            source_ip = detail.get("sourceIPAddress", "unknown")
            user_agent = detail.get("userAgent", "unknown")
            error_code = detail.get("errorCode", "")
            uid = detail.get("userIdentity", {})
            user_identity = uid.get("arn", uid.get("userName", uid.get("principalId", "unknown")))
            user_type = uid.get("type", "unknown")
            region = detail.get("awsRegion", self.region)
            timestamp = str(raw.get("EventTime", datetime.now(timezone.utc)))
            resources = [r.get("ARN", r.get("resourceName", "")) for r in raw.get("Resources", [])]
            severity, description = SUSPICIOUS_ACTIONS[event_name]
            if error_code in ("AccessDenied", "UnauthorizedAccess"):
                description += " [DENIED — possible probing]"
            return ForensicEvent(timestamp=timestamp, event_name=event_name,
                source_ip=source_ip, user_agent=user_agent, user_identity=user_identity,
                user_type=user_type, region=region, severity=severity,
                description=description, error_code=error_code,
                resources=[r for r in resources if r])
        except Exception as e:
            logger.debug(f"Parse error: {e}")
        return None

    def detect_anomalies(self):
        findings = []
        ip_actions = defaultdict(list)
        ip_denials = defaultdict(int)
        identity_ips = defaultdict(set)
        low_sev = {k for k, v in SUSPICIOUS_ACTIONS.items() if v[0] == SEVERITY_LOW}
        for e in self.events:
            ip_actions[e.source_ip].append(e.event_name)
            if "DENIED" in e.description:
                ip_denials[e.source_ip] += 1
            identity_ips[e.user_identity].add(e.source_ip)
        for ip, actions in ip_actions.items():
            if len([a for a in actions if a in low_sev]) >= RECON_THRESHOLD:
                findings.append(f"🔍 RECON BURST — {ip} made {len(actions)} enumeration calls")
        for ip, count in ip_denials.items():
            if count >= 5:
                findings.append(f"🚫 DENIAL STORM — {ip} hit {count} AccessDenied errors")
        for identity, ips in identity_ips.items():
            if len(ips) >= 3 and "unknown" not in identity:
                findings.append(f"🌍 MULTI-LOCATION — {identity} active from {len(ips)} IPs")
        crit_names = {e.event_name for e in self.events if e.severity == SEVERITY_CRITICAL}
        if {"CreateAccessKey", "AttachUserPolicy", "CreateLoginProfile"}.issubset(crit_names):
            findings.append("⛓️  ESCALATION CHAIN — Full account takeover pattern detected")
        if {"DeleteTrail", "StopLogging"}.intersection(crit_names):
            findings.append("🗑️  EVIDENCE TAMPERING — CloudTrail deletion detected")
        return findings

    def build_threat_profiles(self):
        ip_data = defaultdict(lambda: {"events": [], "actions": [], "identities": set(), "timestamps": [], "severities": []})
        sev_rank = {SEVERITY_CRITICAL: 4, SEVERITY_HIGH: 3, SEVERITY_MEDIUM: 2, SEVERITY_LOW: 1}
        for e in self.events:
            d = ip_data[e.source_ip]
            d["events"].append(e); d["actions"].append(e.event_name)
            d["identities"].add(e.user_identity); d["timestamps"].append(e.timestamp)
            d["severities"].append(sev_rank.get(e.severity, 0))
        profiles = []
        sev_map = {4: SEVERITY_CRITICAL, 3: SEVERITY_HIGH, 2: SEVERITY_MEDIUM, 1: SEVERITY_LOW}
        for ip, d in ip_data.items():
            if not d["events"]: continue
            top_actions = sorted(set(d["actions"]), key=lambda a: d["actions"].count(a), reverse=True)[:5]
            profiles.append(ThreatSummary(ip_address=ip, event_count=len(d["events"]),
                unique_actions=len(set(d["actions"])),
                highest_severity=sev_map.get(max(d["severities"]), SEVERITY_LOW),
                first_seen=min(d["timestamps"]), last_seen=max(d["timestamps"]),
                identities_used=list(d["identities"])[:5], top_actions=top_actions))
        return sorted(profiles, key=lambda p: p.event_count, reverse=True)

    def display_events(self):
        if not self.events:
            console.print("[green]No suspicious events detected.[/green]"); return
        for sev in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW]:
            bucket = [e for e in self.events if e.severity == sev]
            if not bucket: continue
            color = SEVERITY_COLOR[sev]
            table = Table(title=f"[{color}]{sev} Events ({len(bucket)})[/{color}]")
            table.add_column("Timestamp", style="dim", width=20)
            table.add_column("Event", style="bold")
            table.add_column("Source IP", style="red")
            table.add_column("Identity", max_width=35)
            table.add_column("Description")
            for e in bucket[:20]:
                table.add_row(e.timestamp[:19], e.event_name, e.source_ip,
                    e.user_identity.split("/")[-1], e.description)
            console.print(table)

    def display_threat_profiles(self, profiles):
        if not profiles: return
        table = Table(title="🕵️  Threat Actor Profiles")
        table.add_column("Source IP", style="red")
        table.add_column("Events", justify="right")
        table.add_column("Highest Sev", style="bold")
        table.add_column("Identities")
        table.add_column("Top Actions")
        for p in profiles[:10]:
            color = SEVERITY_COLOR.get(p.highest_severity, "white")
            table.add_row(p.ip_address, str(p.event_count),
                f"[{color}]{p.highest_severity}[/{color}]",
                ", ".join(i.split("/")[-1] for i in p.identities_used[:3]),
                ", ".join(p.top_actions[:3]))
        console.print(table)

    def display_anomalies(self, anomalies):
        if not anomalies:
            console.print("[green]✓ No behavioral anomalies detected.[/green]"); return
        console.print(Panel("\n".join(f"  {a}" for a in anomalies),
            title="[red bold]⚠️  Behavioral Anomaly Detection[/red bold]", border_style="red"))

    def display_summary(self, anomalies):
        sev_counts = defaultdict(int)
        for e in self.events: sev_counts[e.severity] += 1
        console.print(Panel(f"""
[bold white]Forensic Investigation Complete[/bold white]

[dim]Events scanned:[/dim]     {self.raw_count}
[dim]Suspicious events:[/dim]  {len(self.events)}
[dim]Unique IPs:[/dim]         {len(set(e.source_ip for e in self.events))}
[dim]Anomalies:[/dim]          {len(anomalies)}

[red bold]CRITICAL:[/red bold] {sev_counts[SEVERITY_CRITICAL]}   [orange3]HIGH:[/orange3] {sev_counts[SEVERITY_HIGH]}   [yellow]MEDIUM:[/yellow] {sev_counts[SEVERITY_MEDIUM]}   [cyan]LOW:[/cyan] {sev_counts[SEVERITY_LOW]}
        """, title="[bold cyan]📋 Module 10: Forensic Investigation[/bold cyan]", border_style="cyan"))

    def export_report(self, anomalies, profiles):
        filename = f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report = {
            "report_metadata": {"generated_at": datetime.now(timezone.utc).isoformat(),
                "module": "Module 10 — Forensic Investigation", "account_id": self.account_id},
            "summary": {"total_scanned": self.raw_count, "suspicious": len(self.events),
                "anomalies": len(anomalies),
                "severity_breakdown": {s: sum(1 for e in self.events if e.severity == s)
                    for s in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW]}},
            "anomalies": anomalies,
            "threat_profiles": [{"ip": p.ip_address, "event_count": p.event_count,
                "highest_severity": p.highest_severity, "top_actions": p.top_actions} for p in profiles],
            "events": [e.to_dict() for e in self.events],
        }
        with open(filename, "w") as f:
            json.dump(report, f, indent=2, default=str)
        console.print(f"[green]✓ Forensic report exported: {filename}[/green]")
        return filename

async def run_forensic_investigation(account_id, region="us-east-1", hours=72):
    console.print("\n[bold]--- Module 10: Forensic Investigation Engine ---[/bold]")
    engine = ForensicInvestigationEngine(region=region, account_id=account_id)
    await engine.collect_cloudtrail_events(hours=hours)
    engine.display_events()
    anomalies = engine.detect_anomalies()
    engine.display_anomalies(anomalies)
    profiles = engine.build_threat_profiles()
    engine.display_threat_profiles(profiles)
    engine.display_summary(anomalies)
    engine.export_report(anomalies, profiles)
