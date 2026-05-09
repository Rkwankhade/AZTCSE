import boto3, json, logging, asyncio
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from typing import List
from rich.console import Console
from rich.table import Table

console = Console()
logger = logging.getLogger(__name__)

@dataclass
class HoneypotEvent:
    timestamp: str
    resource_type: str
    resource_name: str
    source_ip: str
    user_agent: str
    action: str
    region: str
    user_identity: str = "unknown"
    severity: str = "CRITICAL"

    def to_dict(self):
        return {"timestamp": self.timestamp, "resource_type": self.resource_type,
                "source_ip": self.source_ip, "action": self.action,
                "user_identity": self.user_identity}

class HoneypotEngine:
    def __init__(self, region="ap-south-1", account_id=""):
        self.region = region
        self.account_id = account_id
        self.events = []
        self.deployed_resources = {}
        self.s3 = boto3.client("s3", region_name=region)
        self.iam = boto3.client("iam", region_name=region)
        self.cloudtrail = boto3.client("cloudtrail", region_name=region)
        self.honeypot_bucket = f"prod-backup-store-{account_id[-6:]}"
        self.honeypot_user = "db-service-account"

    async def deploy_s3_honeypot(self):
        try:
            console.print(f"[yellow]Deploying S3 honeypot: {self.honeypot_bucket}[/yellow]")
            if self.region == "us-east-1":
                self.s3.create_bucket(Bucket=self.honeypot_bucket)
            else:
                self.s3.create_bucket(Bucket=self.honeypot_bucket,
                    CreateBucketConfiguration={"LocationConstraint": self.region})
            for key, content in {"credentials/aws_keys.txt": "FAKE_KEY",
                                  "backup/users_db_2024.sql": "-- fake backup",
                                  "config/production.env": "DB_PASS=fake"}.items():
                self.s3.put_object(Bucket=self.honeypot_bucket, Key=key, Body=content.encode())
            self.s3.put_bucket_tagging(Bucket=self.honeypot_bucket,
                Tagging={"TagSet": [{"Key": "aztcse-honeypot", "Value": "true"}]})
            self.deployed_resources["s3_honeypot"] = self.honeypot_bucket
            console.print(f"[green]S3 honeypot deployed: {self.honeypot_bucket}[/green]")
            return True
        except Exception as e:
            console.print(f"[red]S3 honeypot failed: {e}[/red]")
            return False

    async def deploy_iam_honeypot(self):
        try:
            console.print(f"[yellow]Deploying IAM honeypot: {self.honeypot_user}[/yellow]")
            self.iam.create_user(UserName=self.honeypot_user,
                Tags=[{"Key": "aztcse-honeypot", "Value": "true"}])
            key_response = self.iam.create_access_key(UserName=self.honeypot_user)
            honeypot_key = key_response["AccessKey"]
            self.iam.put_user_policy(UserName=self.honeypot_user,
                PolicyName="HoneypotDenyAll",
                PolicyDocument=json.dumps({"Version": "2012-10-17",
                    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}))
            self.deployed_resources["iam_honeypot"] = self.honeypot_user
            self.deployed_resources["honeypot_key_id"] = honeypot_key["AccessKeyId"]
            console.print(f"[green]IAM honeypot deployed: {self.honeypot_user}[/green]")
            return True
        except Exception as e:
            console.print(f"[red]IAM honeypot failed: {e}[/red]")
            return False

    async def check_cloudtrail_for_honeypot_access(self, hours=24):
        console.print("[yellow]Scanning CloudTrail for honeypot access...[/yellow]")
        try:
            start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
            for attr_key, attr_val, rtype in [
                ("ResourceName", self.deployed_resources.get("s3_honeypot", ""), "S3_HONEYPOT"),
                ("AccessKeyId", self.deployed_resources.get("honeypot_key_id", ""), "IAM_HONEYPOT")]:
                if not attr_val:
                    continue
                paginator = self.cloudtrail.get_paginator("lookup_events")
                for page in paginator.paginate(
                    LookupAttributes=[{"AttributeKey": attr_key, "AttributeValue": attr_val}],
                    StartTime=start_time):
                    for event in page.get("Events", []):
                        self._process_cloudtrail_event(event, rtype)
        except Exception as e:
            console.print(f"[red]CloudTrail error: {e}[/red]")
        return self.events

    def _process_cloudtrail_event(self, event, resource_type):
        try:
            detail = json.loads(event.get("CloudTrailEvent", "{}"))
            source_ip = detail.get("sourceIPAddress", "unknown")
            user_agent = detail.get("userAgent", "unknown")
            user_identity = detail.get("userIdentity", {}).get("arn", "unknown")
            action = event.get("EventName", "unknown")
            timestamp = str(event.get("EventTime", datetime.now()))
            self.events.append(HoneypotEvent(timestamp=timestamp, resource_type=resource_type,
                resource_name=event.get("Resources", [{}])[0].get("ResourceName", "unknown"),
                source_ip=source_ip, user_agent=user_agent,
                action=action, region=self.region, user_identity=user_identity))
            console.print(f"[red bold]HONEYPOT TRIGGERED! IP: {source_ip} Action: {action}[/red bold]")
        except Exception as e:
            logger.debug(f"Event error: {e}")

    def display_results(self):
        if not self.events:
            console.print("[green]No honeypot access detected in last 24 hours.[/green]")
            return
        table = Table(title=f"Honeypot Events ({len(self.events)} total)")
        table.add_column("Timestamp"); table.add_column("Resource")
        table.add_column("Source IP", style="red"); table.add_column("Action")
        for e in self.events:
            table.add_row(e.timestamp[:19], e.resource_type, e.source_ip, e.action)
        console.print(table)

    def export_report(self):
        report = {"generated_at": datetime.now(timezone.utc).isoformat(),
                  "deployed_resources": self.deployed_resources,
                  "total_events": len(self.events),
                  "events": [e.to_dict() for e in self.events],
                  "summary": {"honeypot_triggered": len(self.events) > 0,
                               "unique_ips": list(set(e.source_ip for e in self.events))}}
        with open("honeypot_report.json", "w") as f:
            json.dump(report, f, indent=2)
        console.print("[green]Honeypot report exported: honeypot_report.json[/green]")
        return report

    async def cleanup(self):
        console.print("[yellow]Cleaning up honeypot resources...[/yellow]")
        if "s3_honeypot" in self.deployed_resources:
            try:
                bucket = self.deployed_resources["s3_honeypot"]
                for obj in self.s3.list_objects_v2(Bucket=bucket).get("Contents", []):
                    self.s3.delete_object(Bucket=bucket, Key=obj["Key"])
                self.s3.delete_bucket(Bucket=bucket)
                console.print(f"[green]Deleted S3 honeypot: {bucket}[/green]")
            except Exception as e:
                logger.warning(f"S3 cleanup: {e}")
        if "iam_honeypot" in self.deployed_resources:
            try:
                user = self.deployed_resources["iam_honeypot"]
                for key in self.iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
                    self.iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"])
                for policy in self.iam.list_user_policies(UserName=user)["PolicyNames"]:
                    self.iam.delete_user_policy(UserName=user, PolicyName=policy)
                self.iam.delete_user(UserName=user)
                console.print(f"[green]Deleted IAM honeypot: {user}[/green]")
            except Exception as e:
                logger.warning(f"IAM cleanup: {e}")
        console.print("[green]Honeypot cleanup complete[/green]")

async def run_honeypot(account_id, region="ap-south-1", deploy=True, monitor=True, cleanup=False):
    console.print("\n[bold]--- Module 9: Honeypot Engine ---[/bold]")
    engine = HoneypotEngine(region=region, account_id=account_id)
    if deploy:
        await engine.deploy_s3_honeypot()
        await engine.deploy_iam_honeypot()
    if monitor:
        await engine.check_cloudtrail_for_honeypot_access(hours=24)
        engine.display_results()
        engine.export_report()
    if cleanup:
        await engine.cleanup()
    return engine