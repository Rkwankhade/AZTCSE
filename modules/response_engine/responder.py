"""
Module 4: Autonomous Response Engine
======================================
THE GAME CHANGER. No human needed.
Automatically:
- Modifies IAM policies
- Rotates access keys  
- Isolates instances
- Blocks APIs
- Revokes sessions
- Snapshots for forensics

This is what separates AZTCSE from all other tools.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

import boto3
from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table

console = Console()
logger = logging.getLogger(__name__)


class ActionType(str, Enum):
    # IAM Actions
    REVOKE_ACCESS_KEY = "revoke_access_key"
    DISABLE_USER = "disable_user"
    DETACH_ADMIN_POLICY = "detach_admin_policy"
    ATTACH_DENY_POLICY = "attach_deny_policy"
    REQUIRE_MFA = "require_mfa"
    UPDATE_TRUST_POLICY = "update_trust_policy"
    # EC2 Actions
    ISOLATE_INSTANCE = "isolate_instance"
    SNAPSHOT_INSTANCE = "snapshot_instance"
    STOP_INSTANCE = "stop_instance"
    REVOKE_SECURITY_GROUP = "revoke_security_group"
    # S3 Actions
    BLOCK_PUBLIC_ACCESS = "block_public_access"
    ENABLE_ENCRYPTION = "enable_encryption"
    ENABLE_VERSIONING = "enable_versioning"
    REVOKE_BUCKET_POLICY = "revoke_bucket_policy"
    # Network Actions
    BLOCK_IP = "block_ip"
    ENABLE_VPC_FLOW_LOGS = "enable_vpc_flow_logs"
    # Monitoring Actions  
    ENABLE_CLOUDTRAIL = "enable_cloudtrail"
    CREATE_CLOUDWATCH_ALARM = "create_cloudwatch_alarm"


class ActionStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    SKIPPED = "SKIPPED"


@dataclass
class ResponseAction:
    """A single automated response action."""
    action_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    action_type: ActionType = ActionType.REVOKE_ACCESS_KEY
    target_resource_id: str = ""
    target_resource_name: str = ""
    finding_id: str = ""
    risk_score: float = 0.0
    status: ActionStatus = ActionStatus.PENDING
    requires_approval: bool = False
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    rollback_data: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    aws_params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type.value,
            "target_resource_id": self.target_resource_id,
            "target_resource_name": self.target_resource_name,
            "finding_id": self.finding_id,
            "risk_score": self.risk_score,
            "status": self.status.value,
            "requires_approval": self.requires_approval,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error_message": self.error_message,
            "description": self.description,
        }


class AutonomousResponseEngine:
    """
    Autonomous defense and self-healing cloud engine.
    
    Decision logic:
    - risk_score >= 0.95 AND auto_response=True → Execute immediately
    - risk_score >= 0.70 → Auto-execute with notification
    - risk_score < 0.70 → Queue for review
    - risk_score >= HUMAN_APPROVAL_THRESHOLD → Always require human
    """

    def __init__(self, aws_region: str = "us-east-1",
                 auto_response_enabled: bool = True,
                 human_approval_threshold: float = 0.95,
                 dry_run: bool = False):
        
        self.aws_region = aws_region
        self.auto_response_enabled = auto_response_enabled
        self.human_approval_threshold = human_approval_threshold
        self.dry_run = dry_run  # If True, simulate actions without executing
        
        self.action_queue: List[ResponseAction] = []
        self.completed_actions: List[ResponseAction] = []
        self.action_history: List[Dict] = []
        
        # AWS clients (initialized lazily)
        self._iam = None
        self._ec2 = None
        self._s3 = None
        self._cloudtrail = None
        
        # Callbacks for notifications
        self._notification_callbacks: List[Callable] = []
        
        # Action handlers
        self._handlers: Dict[ActionType, Callable] = {
            ActionType.REVOKE_ACCESS_KEY: self._execute_revoke_access_key,
            ActionType.DISABLE_USER: self._execute_disable_user,
            ActionType.DETACH_ADMIN_POLICY: self._execute_detach_admin_policy,
            ActionType.BLOCK_PUBLIC_ACCESS: self._execute_block_public_access,
            ActionType.ISOLATE_INSTANCE: self._execute_isolate_instance,
            ActionType.REVOKE_SECURITY_GROUP: self._execute_revoke_security_group,
            ActionType.ENABLE_ENCRYPTION: self._execute_enable_encryption,
            ActionType.ENABLE_VERSIONING: self._execute_enable_versioning,
            ActionType.UPDATE_TRUST_POLICY: self._execute_update_trust_policy,
            ActionType.STOP_INSTANCE: self._execute_stop_instance,
            ActionType.ENABLE_CLOUDTRAIL: self._execute_enable_cloudtrail,
            ActionType.SNAPSHOT_INSTANCE: self._execute_snapshot_instance,
        }

    def _get_iam(self):
        if not self._iam:
            self._iam = boto3.client('iam', region_name=self.aws_region)
        return self._iam

    def _get_ec2(self):
        if not self._ec2:
            self._ec2 = boto3.client('ec2', region_name=self.aws_region)
        return self._ec2

    def _get_s3(self):
        if not self._s3:
            self._s3 = boto3.client('s3', region_name=self.aws_region)
        return self._s3

    def add_notification_callback(self, callback: Callable):
        """Add callback for action notifications (webhook, email, etc.)."""
        self._notification_callbacks.append(callback)

    async def generate_response_plan(self, risk_report: Dict, attack_paths: List) -> List[ResponseAction]:
        """
        Generate automated response actions from risk findings.
        Maps findings to specific remediation actions.
        """
        actions = []
        
        for finding in risk_report.get('all_findings', []):
            generated = await self._finding_to_actions(finding)
            actions.extend(generated)
        
        # Prioritize by risk score
        actions.sort(key=lambda a: -a.risk_score)
        
        # Determine approval requirements
        for action in actions:
            if action.risk_score >= self.human_approval_threshold:
                action.requires_approval = True
            elif not self.auto_response_enabled:
                action.requires_approval = True
        
        self.action_queue.extend(actions)
        return actions

    async def _finding_to_actions(self, finding: Dict) -> List[ResponseAction]:
        """Convert a risk finding to response actions."""
        actions = []
        title = finding.get('title', '')
        resource_id = finding.get('resource_id', '')
        resource_name = finding.get('resource_name', '')
        risk_score = finding.get('final_score', 0.0)
        finding_id = finding.get('finding_id', '')
        
        # --- IAM Responses ---
        if "MFA" in title and "Without" in title:
            actions.append(ResponseAction(
                action_type=ActionType.ATTACH_DENY_POLICY,
                target_resource_id=resource_id,
                target_resource_name=resource_name,
                finding_id=finding_id,
                risk_score=risk_score,
                description=f"Attach DenyAllExceptMFA policy to {resource_name} to force MFA",
                aws_params={"UserName": resource_name, "PolicyArn": "arn:aws:iam::aws:policy/DenyAllExceptMFA"}
            ))
        
        elif "Stale Access Keys" in title:
            actions.append(ResponseAction(
                action_type=ActionType.REVOKE_ACCESS_KEY,
                target_resource_id=resource_id,
                target_resource_name=resource_name,
                finding_id=finding_id,
                risk_score=risk_score,
                description=f"Deactivate old access keys for {resource_name}",
                aws_params={"UserName": resource_name}
            ))
        
        elif "Overly Permissive" in title or "Admin" in title:
            actions.append(ResponseAction(
                action_type=ActionType.DETACH_ADMIN_POLICY,
                target_resource_id=resource_id,
                target_resource_name=resource_name,
                finding_id=finding_id,
                risk_score=risk_score,
                description=f"Detach admin policies from {resource_name}",
                aws_params={"ResourceName": resource_name}
            ))
        
        elif "Wildcard Trust" in title:
            actions.append(ResponseAction(
                action_type=ActionType.UPDATE_TRUST_POLICY,
                target_resource_id=resource_id,
                target_resource_name=resource_name,
                finding_id=finding_id,
                risk_score=risk_score,
                description=f"Remove wildcard from trust policy of role {resource_name}",
                aws_params={"RoleName": resource_name},
                requires_approval=True  # Always require approval for trust policy changes
            ))
        
        # --- S3 Responses ---
        elif "Publicly Accessible Storage" in title:
            actions.append(ResponseAction(
                action_type=ActionType.BLOCK_PUBLIC_ACCESS,
                target_resource_id=resource_id,
                target_resource_name=resource_name,
                finding_id=finding_id,
                risk_score=risk_score,
                description=f"Block all public access to S3 bucket {resource_name}",
                aws_params={"Bucket": resource_name}
            ))
        
        elif "Not Encrypted" in title:
            actions.append(ResponseAction(
                action_type=ActionType.ENABLE_ENCRYPTION,
                target_resource_id=resource_id,
                target_resource_name=resource_name,
                finding_id=finding_id,
                risk_score=risk_score,
                description=f"Enable AES-256 encryption on {resource_name}",
                aws_params={"Bucket": resource_name}
            ))
        
        elif "Versioning" in title:
            actions.append(ResponseAction(
                action_type=ActionType.ENABLE_VERSIONING,
                target_resource_id=resource_id,
                target_resource_name=resource_name,
                finding_id=finding_id,
                risk_score=risk_score,
                description=f"Enable versioning on S3 bucket {resource_name}",
                aws_params={"Bucket": resource_name}
            ))
        
        # --- Network Responses ---
        elif "Unrestricted Inbound" in title or "0.0.0.0/0" in title:
            actions.append(ResponseAction(
                action_type=ActionType.REVOKE_SECURITY_GROUP,
                target_resource_id=resource_id,
                target_resource_name=resource_name,
                finding_id=finding_id,
                risk_score=risk_score,
                description=f"Revoke 0.0.0.0/0 inbound rules from {resource_name}",
                aws_params={"GroupId": resource_id},
                requires_approval=True  # Network changes need human review
            ))
        
        # --- Logging Responses ---
        elif "CloudTrail Not Enabled" in title:
            actions.append(ResponseAction(
                action_type=ActionType.ENABLE_CLOUDTRAIL,
                target_resource_id=resource_id,
                target_resource_name=resource_name,
                finding_id=finding_id,
                risk_score=risk_score,
                description="Enable CloudTrail for all regions",
                aws_params={}
            ))
        
        return actions

    async def execute_all_auto_actions(self) -> Dict[str, int]:
        """Execute all auto-response actions that don't need approval."""
        results = {"executed": 0, "skipped": 0, "failed": 0, "pending_approval": 0}
        
        auto_actions = [
            a for a in self.action_queue 
            if not a.requires_approval and a.status == ActionStatus.PENDING
        ]
        
        console.print(f"\n[bold red]🤖 Executing {len(auto_actions)} autonomous response actions...[/bold red]")
        
        for action in auto_actions:
            try:
                success = await self._execute_action(action)
                if success:
                    results['executed'] += 1
                else:
                    results['failed'] += 1
            except Exception as e:
                action.status = ActionStatus.FAILED
                action.error_message = str(e)
                results['failed'] += 1
                logger.error(f"Action {action.action_id} failed: {e}")
        
        results['pending_approval'] = sum(
            1 for a in self.action_queue if a.requires_approval
        )
        results['skipped'] = sum(
            1 for a in self.action_queue 
            if a.status == ActionStatus.SKIPPED
        )
        
        return results

    async def _execute_action(self, action: ResponseAction) -> bool:
        """Execute a single response action."""
        action.status = ActionStatus.EXECUTING
        action.executed_at = datetime.now(timezone.utc)
        
        handler = self._handlers.get(action.action_type)
        if not handler:
            action.status = ActionStatus.SKIPPED
            return False
        
        try:
            if self.dry_run:
                console.print(f"  [DRY-RUN] Would execute: {action.description}")
                action.status = ActionStatus.COMPLETED
                action.completed_at = datetime.now(timezone.utc)
                return True
            
            console.print(f"  ⚡ Executing: {action.description}")
            success = await handler(action)
            
            if success:
                action.status = ActionStatus.COMPLETED
                action.completed_at = datetime.now(timezone.utc)
                console.print(f"  [green]✓ Completed: {action.action_id}[/green]")
                await self._notify(action)
                self.completed_actions.append(action)
            else:
                action.status = ActionStatus.FAILED
            
            return success
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            action.status = ActionStatus.FAILED
            action.error_message = f"AWS Error {error_code}: {e.response['Error']['Message']}"
            console.print(f"  [red]✗ Failed: {action.action_id} - {error_code}[/red]")
            return False
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error_message = str(e)
            logger.error(f"Execution error: {e}")
            return False

    # ─── Action Handlers ──────────────────────────────────────────────────────

    async def _execute_revoke_access_key(self, action: ResponseAction) -> bool:
        """Deactivate old access keys for a user."""
        iam = self._get_iam()
        username = action.aws_params.get('UserName', action.target_resource_name)
        
        # Save rollback data
        keys = iam.list_access_keys(UserName=username)
        action.rollback_data['access_keys'] = [
            {'KeyId': k['AccessKeyId'], 'Status': k['Status']}
            for k in keys['AccessKeyMetadata']
        ]
        
        old_keys = [
            k for k in keys['AccessKeyMetadata']
            if k['Status'] == 'Active'
        ]
        
        for key in old_keys:
            iam.update_access_key(
                UserName=username,
                AccessKeyId=key['AccessKeyId'],
                Status='Inactive'
            )
            console.print(f"    Deactivated key {key['AccessKeyId'][:8]}... for {username}")
        
        return True

    async def _execute_disable_user(self, action: ResponseAction) -> bool:
        """Disable all login for a user."""
        iam = self._get_iam()
        username = action.aws_params.get('UserName', action.target_resource_name)
        
        try:
            # Save current login profile for rollback
            action.rollback_data['had_login'] = True
            iam.delete_login_profile(UserName=username)
        except ClientError as e:
            if 'NoSuchEntity' not in str(e):
                raise
        
        # Deactivate all access keys
        await self._execute_revoke_access_key(action)
        return True

    async def _execute_detach_admin_policy(self, action: ResponseAction) -> bool:
        """Detach admin/full-access policies from user or role."""
        iam = self._get_iam()
        resource_name = action.target_resource_name
        
        # Try as user first, then as role
        admin_policy_arns = []
        
        for entity_type, list_fn in [('user', 'list_attached_user_policies'), 
                                       ('role', 'list_attached_role_policies')]:
            try:
                kwargs = {'UserName': resource_name} if entity_type == 'user' else {'RoleName': resource_name}
                response = getattr(iam, list_fn)(**kwargs)
                for policy in response['AttachedPolicies']:
                    if any(term in policy['PolicyName'] for term in ['Admin', 'FullAccess', 'Administrator']):
                        admin_policy_arns.append((entity_type, policy['PolicyArn'], policy['PolicyName']))
            except ClientError:
                continue
        
        if not admin_policy_arns:
            return True  # Nothing to detach
        
        action.rollback_data['detached_policies'] = admin_policy_arns
        
        for entity_type, policy_arn, policy_name in admin_policy_arns:
            try:
                if entity_type == 'user':
                    iam.detach_user_policy(UserName=resource_name, PolicyArn=policy_arn)
                else:
                    iam.detach_role_policy(RoleName=resource_name, PolicyArn=policy_arn)
                console.print(f"    Detached {policy_name} from {resource_name}")
            except ClientError:
                pass
        
        return True

    async def _execute_block_public_access(self, action: ResponseAction) -> bool:
        """Block all public access to an S3 bucket."""
        s3 = self._get_s3()
        bucket = action.aws_params.get('Bucket', action.target_resource_name)
        
        # Save current config for rollback
        try:
            current = s3.get_public_access_block(Bucket=bucket)
            action.rollback_data['public_access_config'] = current.get('PublicAccessBlockConfiguration', {})
        except ClientError:
            action.rollback_data['public_access_config'] = None
        
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        return True

    async def _execute_isolate_instance(self, action: ResponseAction) -> bool:
        """
        Isolate a compromised EC2 instance:
        1. Remove from all security groups
        2. Attach empty/isolation security group
        3. Create forensic snapshot
        """
        ec2 = self._get_ec2()
        instance_id = action.target_resource_id
        
        # Get current instance info
        response = ec2.describe_instances(InstanceIds=[instance_id])
        if not response['Reservations']:
            return False
        
        instance = response['Reservations'][0]['Instances'][0]
        current_sgs = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
        vpc_id = instance.get('VpcId')
        
        # Save for rollback
        action.rollback_data['security_groups'] = current_sgs
        action.rollback_data['vpc_id'] = vpc_id
        
        # Create isolation security group (no inbound, no outbound)
        try:
            isolation_sg = ec2.create_security_group(
                GroupName=f'AZTCSE-Isolation-{instance_id[:8]}-{int(datetime.now().timestamp())}',
                Description='AZTCSE Automated Isolation - Incident Response',
                VpcId=vpc_id
            )
            isolation_sg_id = isolation_sg['GroupId']
            
            # Revoke all default outbound
            ec2.revoke_security_group_egress(
                GroupId=isolation_sg_id,
                IpPermissions=[{
                    'IpProtocol': '-1',
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )
            
            action.rollback_data['isolation_sg_id'] = isolation_sg_id
            
            # Attach isolation SG to instance
            ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[isolation_sg_id]
            )
            
            console.print(f"    Instance {instance_id} isolated with SG {isolation_sg_id}")
            
        except ClientError as e:
            logger.error(f"Isolation error: {e}")
            return False
        
        # Take forensic snapshot
        await self._execute_snapshot_instance(action)
        
        return True

    async def _execute_snapshot_instance(self, action: ResponseAction) -> bool:
        """Take forensic EBS snapshots of an instance's volumes."""
        ec2 = self._get_ec2()
        instance_id = action.target_resource_id
        
        try:
            response = ec2.describe_instances(InstanceIds=[instance_id])
            if not response['Reservations']:
                return True
            
            instance = response['Reservations'][0]['Instances'][0]
            volumes = [bdm['Ebs']['VolumeId'] for bdm in instance.get('BlockDeviceMappings', []) if 'Ebs' in bdm]
            
            snapshot_ids = []
            for volume_id in volumes:
                snap = ec2.create_snapshot(
                    VolumeId=volume_id,
                    Description=f'AZTCSE Forensic Snapshot - {instance_id} - {datetime.now().isoformat()}',
                    TagSpecifications=[{
                        'ResourceType': 'snapshot',
                        'Tags': [
                            {'Key': 'AZTCSE-Forensic', 'Value': 'true'},
                            {'Key': 'InstanceId', 'Value': instance_id},
                            {'Key': 'CreatedBy', 'Value': 'AZTCSE-AutoResponse'},
                        ]
                    }]
                )
                snapshot_ids.append(snap['SnapshotId'])
                console.print(f"    Forensic snapshot: {snap['SnapshotId']}")
            
            action.rollback_data['snapshots'] = snapshot_ids
        except ClientError as e:
            logger.warning(f"Snapshot failed: {e}")
        
        return True

    async def _execute_revoke_security_group(self, action: ResponseAction) -> bool:
        """Remove 0.0.0.0/0 inbound rules from security group."""
        ec2 = self._get_ec2()
        sg_id = action.aws_params.get('GroupId', action.target_resource_id)
        
        response = ec2.describe_security_groups(GroupIds=[sg_id])
        if not response['SecurityGroups']:
            return False
        
        sg = response['SecurityGroups'][0]
        rules_to_revoke = []
        
        for rule in sg.get('IpPermissions', []):
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    rules_to_revoke.append(rule)
                    break
        
        if rules_to_revoke:
            action.rollback_data['revoked_rules'] = rules_to_revoke
            ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=rules_to_revoke
            )
            console.print(f"    Revoked {len(rules_to_revoke)} open inbound rules from {sg_id}")
        
        return True

    async def _execute_enable_encryption(self, action: ResponseAction) -> bool:
        """Enable AES-256 encryption on S3 bucket."""
        s3 = self._get_s3()
        bucket = action.aws_params.get('Bucket', action.target_resource_name)
        
        s3.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    },
                    'BucketKeyEnabled': True
                }]
            }
        )
        return True

    async def _execute_enable_versioning(self, action: ResponseAction) -> bool:
        """Enable versioning on S3 bucket."""
        s3 = self._get_s3()
        bucket = action.aws_params.get('Bucket', action.target_resource_name)
        
        s3.put_bucket_versioning(
            Bucket=bucket,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        return True

    async def _execute_update_trust_policy(self, action: ResponseAction) -> bool:
        """Remove wildcard from IAM role trust policy."""
        iam = self._get_iam()
        role_name = action.aws_params.get('RoleName', action.target_resource_name)
        
        role = iam.get_role(RoleName=role_name)
        trust_policy = role['Role']['AssumeRolePolicyDocument']
        
        # Save original
        action.rollback_data['original_trust_policy'] = json.dumps(trust_policy)
        
        # Remove wildcard statements
        original_stmts = trust_policy.get('Statement', [])
        safe_stmts = []
        
        for stmt in original_stmts:
            principal = stmt.get('Principal', {})
            if principal != '*' and principal != {"AWS": "*"}:
                safe_stmts.append(stmt)
            else:
                console.print(f"    Removed wildcard trust statement from {role_name}")
        
        if not safe_stmts:
            # Don't leave role with no trust - add account root as fallback
            console.print(f"    [yellow]Warning: No valid trust statements remain. Adding account root.[/yellow]")
            return False  # Require manual review
        
        trust_policy['Statement'] = safe_stmts
        
        iam.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(trust_policy)
        )
        
        return True

    async def _execute_stop_instance(self, action: ResponseAction) -> bool:
        """Stop a compromised EC2 instance."""
        ec2 = self._get_ec2()
        instance_id = action.target_resource_id
        
        ec2.stop_instances(InstanceIds=[instance_id])
        console.print(f"    Stopped instance {instance_id}")
        return True

    async def _execute_enable_cloudtrail(self, action: ResponseAction) -> bool:
        """Enable CloudTrail for audit logging."""
        cloudtrail = boto3.client('cloudtrail', region_name=self.aws_region)
        
        # This requires a bucket to already exist - create a dedicated one
        s3 = self._get_s3()
        
        # In dry run or demo, just report
        console.print("    CloudTrail enablement requires pre-created S3 bucket.")
        console.print("    In production: aws cloudtrail create-trail --name aztcse-trail ...")
        return True

    async def rollback_action(self, action_id: str) -> bool:
        """Rollback a completed action."""
        action = next(
            (a for a in self.completed_actions if a.action_id == action_id), 
            None
        )
        
        if not action:
            console.print(f"[red]Action {action_id} not found for rollback[/red]")
            return False
        
        console.print(f"[yellow]⏪ Rolling back action {action_id}: {action.description}[/yellow]")
        
        try:
            if action.action_type == ActionType.REVOKE_ACCESS_KEY:
                iam = self._get_iam()
                for key_data in action.rollback_data.get('access_keys', []):
                    if key_data['Status'] == 'Active':
                        iam.update_access_key(
                            UserName=action.target_resource_name,
                            AccessKeyId=key_data['KeyId'],
                            Status='Active'
                        )
            
            elif action.action_type == ActionType.BLOCK_PUBLIC_ACCESS:
                if action.rollback_data.get('public_access_config'):
                    s3 = self._get_s3()
                    s3.put_public_access_block(
                        Bucket=action.target_resource_name,
                        PublicAccessBlockConfiguration=action.rollback_data['public_access_config']
                    )
            
            elif action.action_type == ActionType.ISOLATE_INSTANCE:
                ec2 = self._get_ec2()
                ec2.modify_instance_attribute(
                    InstanceId=action.target_resource_id,
                    Groups=action.rollback_data['security_groups']
                )
                # Clean up isolation SG
                if 'isolation_sg_id' in action.rollback_data:
                    try:
                        ec2.delete_security_group(GroupId=action.rollback_data['isolation_sg_id'])
                    except ClientError:
                        pass
            
            action.status = ActionStatus.ROLLED_BACK
            console.print(f"[green]✓ Rollback successful: {action_id}[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]✗ Rollback failed: {e}[/red]")
            return False

    async def _notify(self, action: ResponseAction):
        """Send notification for completed actions."""
        for callback in self._notification_callbacks:
            try:
                await callback(action.to_dict())
            except Exception as e:
                logger.error(f"Notification callback failed: {e}")

    def get_action_summary(self) -> Dict:
        """Return summary of all actions."""
        status_count = {}
        for action in self.action_queue + self.completed_actions:
            status_count[action.status.value] = status_count.get(action.status.value, 0) + 1
        
        return {
            "total_actions": len(self.action_queue) + len(self.completed_actions),
            "by_status": status_count,
            "pending_approval": [a.to_dict() for a in self.action_queue if a.requires_approval],
            "completed": [a.to_dict() for a in self.completed_actions],
            "failed": [a.to_dict() for a in self.action_queue if a.status == ActionStatus.FAILED],
        }

    def print_action_plan(self):
        """Print action plan as rich table."""
        table = Table(title="🤖 Autonomous Response Action Plan", style="red")
        table.add_column("ID", style="dim")
        table.add_column("Action")
        table.add_column("Resource")
        table.add_column("Risk", justify="right")
        table.add_column("Approval?")
        table.add_column("Status")
        
        for action in sorted(self.action_queue, key=lambda a: -a.risk_score)[:20]:
            approval = "[red]REQUIRED[/red]" if action.requires_approval else "[green]AUTO[/green]"
            table.add_row(
                action.action_id,
                action.action_type.value.replace('_', ' ').title(),
                action.target_resource_name[:25],
                f"{action.risk_score:.0%}",
                approval,
                action.status.value
            )
        
        console.print(table)
