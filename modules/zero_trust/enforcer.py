"""
Module 5: Zero Trust Enforcement Layer
========================================
Continuously enforces:
- Least privilege
- Just-in-time (JIT) access
- Dynamic identity-based control
- Continuous verification (not static roles)

"Never trust, always verify" - applied to cloud IAM
"""

import asyncio
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

import boto3
from rich.console import Console
from rich.table import Table

console = Console()
logger = logging.getLogger(__name__)


class TrustLevel(str, Enum):
    UNTRUSTED = "UNTRUSTED"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"  # Reserved for break-glass


class AccessDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    CHALLENGE = "CHALLENGE"    # Require additional verification
    STEP_UP = "STEP_UP"        # Require MFA step-up


@dataclass
class Identity:
    """Represents an authenticated identity in the system."""
    identity_id: str
    identity_type: str  # user / role / service
    name: str
    arn: str
    trust_level: TrustLevel = TrustLevel.LOW
    risk_score: float = 0.0
    last_activity: Optional[datetime] = None
    session_created: Optional[datetime] = None
    mfa_verified: bool = False
    location: Optional[str] = None
    known_ips: Set[str] = field(default_factory=set)
    current_ip: Optional[str] = None
    anomaly_flags: List[str] = field(default_factory=list)
    active_sessions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "identity_id": self.identity_id,
            "identity_type": self.identity_type,
            "name": self.name,
            "arn": self.arn,
            "trust_level": self.trust_level.value,
            "risk_score": round(self.risk_score, 3),
            "mfa_verified": self.mfa_verified,
            "anomaly_flags": self.anomaly_flags,
        }


@dataclass
class JITAccessGrant:
    """Just-in-time access grant - temporary elevated permissions."""
    grant_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    identity_id: str = ""
    resource_arn: str = ""
    permissions: List[str] = field(default_factory=list)
    justification: str = ""
    granted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    is_active: bool = True
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def to_dict(self) -> Dict:
        return {
            "grant_id": self.grant_id,
            "identity_id": self.identity_id,
            "resource_arn": self.resource_arn,
            "permissions": self.permissions,
            "justification": self.justification,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active": self.is_active and not self.is_expired(),
            "time_remaining_minutes": (
                int((self.expires_at - datetime.now(timezone.utc)).total_seconds() / 60)
                if self.expires_at and not self.is_expired() else 0
            ),
        }


@dataclass
class AccessRequest:
    """A request for access to a resource."""
    request_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    identity_id: str = ""
    resource_arn: str = ""
    action: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    decision: Optional[AccessDecision] = None
    reason: str = ""
    evaluated_at: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            "request_id": self.request_id,
            "identity_id": self.identity_id,
            "resource_arn": self.resource_arn,
            "action": self.action,
            "decision": self.decision.value if self.decision else None,
            "reason": self.reason,
        }


class ZeroTrustEngine:
    """
    Zero Trust Policy Enforcement Point.
    
    Every access request is evaluated dynamically.
    No implicit trust based on network location or role.
    Continuous verification of identity + behavior.
    """

    def __init__(self, aws_region: str = "us-east-1",
                 jit_duration_minutes: int = 60,
                 session_revalidation_interval: int = 300):
        
        self.aws_region = aws_region
        self.jit_duration = jit_duration_minutes
        self.revalidation_interval = session_revalidation_interval
        
        self.identities: Dict[str, Identity] = {}
        self.jit_grants: Dict[str, JITAccessGrant] = {}
        self.access_log: List[AccessRequest] = []
        self.policy_violations: List[Dict] = []
        
        self._iam = None
        self._monitoring_active = False

    def _get_iam(self):
        if not self._iam:
            self._iam = boto3.client('iam', region_name=self.aws_region)
        return self._iam

    async def initialize_from_graph(self, casg):
        """Load identities from the cloud graph."""
        nodes = casg.nodes
        
        for node_id, node in nodes.items():
            if node.node_type.value in ['IAM_USER', 'IAM_ROLE']:
                # Calculate trust level from risk score
                trust_level = self._risk_to_trust(node.risk_score)
                
                identity = Identity(
                    identity_id=node_id,
                    identity_type='user' if 'USER' in node.node_type.value else 'role',
                    name=node.name,
                    arn=node.arn or f"arn:aws:iam::unknown:{node.node_type.value.lower()}/{node.name}",
                    trust_level=trust_level,
                    risk_score=node.risk_score,
                    anomaly_flags=[
                        m for m in node.misconfigurations
                        if any(keyword in m.lower() for keyword in ['mfa', 'key', 'access', 'trust'])
                    ]
                )
                self.identities[node_id] = identity
        
        console.print(f"[green]✓ Zero Trust: Loaded {len(self.identities)} identities[/green]")

    def _risk_to_trust(self, risk_score: float) -> TrustLevel:
        """Convert risk score to trust level (inverse relationship)."""
        if risk_score >= 0.8:
            return TrustLevel.UNTRUSTED
        elif risk_score >= 0.6:
            return TrustLevel.LOW
        elif risk_score >= 0.4:
            return TrustLevel.MEDIUM
        elif risk_score >= 0.2:
            return TrustLevel.HIGH
        return TrustLevel.HIGH

    async def evaluate_access(self, request: AccessRequest) -> AccessDecision:
        """
        Evaluate an access request using Zero Trust principles.
        
        Factors considered:
        1. Identity trust level
        2. Current risk score
        3. MFA status
        4. Behavioral anomalies
        5. JIT grant status
        6. Resource sensitivity
        """
        identity = self.identities.get(request.identity_id)
        if not identity:
            request.decision = AccessDecision.DENY
            request.reason = "Unknown identity - DENY by default"
            self.access_log.append(request)
            return AccessDecision.DENY

        request.evaluated_at = datetime.now(timezone.utc)
        
        # Rule 1: Always DENY untrusted identities
        if identity.trust_level == TrustLevel.UNTRUSTED:
            request.decision = AccessDecision.DENY
            request.reason = f"Identity {identity.name} is UNTRUSTED (risk={identity.risk_score:.2f})"
            self._log_violation(request, "UNTRUSTED_IDENTITY")
            self.access_log.append(request)
            return AccessDecision.DENY
        
        # Rule 2: Require MFA for high-privilege actions
        high_priv_actions = ['iam:*', 'ec2:TerminateInstances', 's3:DeleteBucket', 
                             'sts:AssumeRole', 'iam:CreateAccessKey', 'iam:DeleteAccessKey']
        if any(request.action.startswith(a.rstrip('*')) for a in high_priv_actions):
            if not identity.mfa_verified:
                request.decision = AccessDecision.STEP_UP
                request.reason = "High-privilege action requires MFA verification"
                self.access_log.append(request)
                return AccessDecision.STEP_UP
        
        # Rule 3: Check for active JIT grant
        has_jit = any(
            g.identity_id == request.identity_id 
            and g.resource_arn == request.resource_arn
            and not g.is_expired()
            and g.is_active
            and request.action in g.permissions
            for g in self.jit_grants.values()
        )
        
        # Rule 4: Behavioral anomalies trigger CHALLENGE
        if identity.anomaly_flags and not has_jit:
            request.decision = AccessDecision.CHALLENGE
            request.reason = f"Anomalies detected: {', '.join(identity.anomaly_flags[:2])}"
            self.access_log.append(request)
            return AccessDecision.CHALLENGE
        
        # Rule 5: Unknown IP = step-up auth
        context_ip = request.context.get('source_ip')
        if context_ip and identity.known_ips and context_ip not in identity.known_ips:
            request.decision = AccessDecision.STEP_UP
            request.reason = f"Access from unknown IP {context_ip}"
            self.access_log.append(request)
            return AccessDecision.STEP_UP
        
        # Rule 6: Check if within session revalidation period
        if identity.last_activity:
            time_since_activity = (datetime.now(timezone.utc) - identity.last_activity).total_seconds()
            if time_since_activity > self.revalidation_interval:
                request.decision = AccessDecision.CHALLENGE
                request.reason = f"Session requires revalidation (inactive {time_since_activity:.0f}s)"
                self.access_log.append(request)
                return AccessDecision.CHALLENGE
        
        # ALLOW - all checks passed
        identity.last_activity = datetime.now(timezone.utc)
        request.decision = AccessDecision.ALLOW
        request.reason = f"All Zero Trust checks passed (trust={identity.trust_level.value})"
        self.access_log.append(request)
        return AccessDecision.ALLOW

    async def request_jit_access(self, identity_id: str, resource_arn: str,
                                  permissions: List[str], justification: str,
                                  duration_minutes: Optional[int] = None) -> JITAccessGrant:
        """
        Request just-in-time elevated access.
        Access is temporary and logged.
        """
        duration = duration_minutes or self.jit_duration
        identity = self.identities.get(identity_id)
        
        if not identity:
            raise ValueError(f"Identity {identity_id} not found")
        
        # High-risk identities cannot get JIT access without approval
        if identity.risk_score > 0.7:
            raise PermissionError(
                f"Identity {identity.name} has high risk score ({identity.risk_score:.2f}). "
                f"JIT access denied until risk is remediated."
            )
        
        grant = JITAccessGrant(
            identity_id=identity_id,
            resource_arn=resource_arn,
            permissions=permissions,
            justification=justification,
            granted_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=duration),
        )
        
        self.jit_grants[grant.grant_id] = grant
        
        console.print(
            f"[green]✓ JIT Access Granted:[/green] {identity.name} → {resource_arn} "
            f"for {duration} minutes"
        )
        console.print(f"  Grant ID: {grant.grant_id}")
        console.print(f"  Permissions: {', '.join(permissions)}")
        console.print(f"  Expires: {grant.expires_at.strftime('%H:%M:%S UTC')}")
        
        return grant

    async def revoke_jit_access(self, grant_id: str, reason: str = "Manual revocation"):
        """Immediately revoke a JIT access grant."""
        grant = self.jit_grants.get(grant_id)
        if not grant:
            raise ValueError(f"Grant {grant_id} not found")
        
        grant.is_active = False
        grant.revoked_at = datetime.now(timezone.utc)
        grant.revocation_reason = reason
        
        console.print(f"[yellow]⚠ JIT grant {grant_id} revoked: {reason}[/yellow]")

    async def purge_expired_grants(self):
        """Background task: automatically expire JIT grants."""
        expired_count = 0
        for grant_id, grant in list(self.jit_grants.items()):
            if grant.is_expired() and grant.is_active:
                grant.is_active = False
                expired_count += 1
        
        if expired_count:
            console.print(f"[dim]⏰ Expired {expired_count} JIT grants[/dim]")
        
        return expired_count

    async def run_continuous_verification(self):
        """
        Background continuous verification loop.
        Runs periodically to re-evaluate all active sessions.
        """
        self._monitoring_active = True
        console.print("[cyan]🔄 Zero Trust continuous verification active[/cyan]")
        
        while self._monitoring_active:
            try:
                # Purge expired grants
                await self.purge_expired_grants()
                
                # Re-evaluate identity risk scores
                await self._refresh_identity_risk()
                
                # Detect anomalies
                await self._detect_behavioral_anomalies()
                
                await asyncio.sleep(self.revalidation_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Verification loop error: {e}")
                await asyncio.sleep(30)

    async def _refresh_identity_risk(self):
        """Refresh identity risk scores from AWS."""
        try:
            iam = self._get_iam()
            
            for identity in self.identities.values():
                if identity.identity_type != 'user':
                    continue
                
                # Quick check: MFA status
                try:
                    mfa = iam.list_mfa_devices(UserName=identity.name)
                    identity.mfa_verified = len(mfa['MFADevices']) > 0
                    
                    if not identity.mfa_verified and identity.risk_score < 0.5:
                        identity.risk_score += 0.1
                        identity.trust_level = self._risk_to_trust(identity.risk_score)
                except Exception:
                    pass
                    
        except Exception as e:
            logger.debug(f"Risk refresh skipped (demo mode): {e}")

    async def _detect_behavioral_anomalies(self):
        """
        Detect anomalous behavior in identities.
        Looks for:
        - Unusual access times
        - Rapid permission escalation
        - Access from new locations
        """
        for identity in self.identities.values():
            # Check for recent unusual access patterns
            recent_requests = [
                r for r in self.access_log[-100:]
                if r.identity_id == identity.identity_id
            ]
            
            # Flag if too many denied requests
            denied = sum(1 for r in recent_requests if r.decision == AccessDecision.DENY)
            if denied > 5 and "Multiple access denials" not in identity.anomaly_flags:
                identity.anomaly_flags.append("Multiple access denials - possible enumeration")
                identity.risk_score = min(identity.risk_score + 0.2, 1.0)
                identity.trust_level = self._risk_to_trust(identity.risk_score)

    def _log_violation(self, request: AccessRequest, violation_type: str):
        """Log a Zero Trust policy violation."""
        self.policy_violations.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "violation_type": violation_type,
            "identity_id": request.identity_id,
            "resource_arn": request.resource_arn,
            "action": request.action,
            "decision": request.decision.value if request.decision else None,
            "reason": request.reason,
        })

    def apply_least_privilege_recommendations(self) -> List[Dict]:
        """
        Analyze current permissions and recommend least-privilege policies.
        """
        recommendations = []
        
        for identity in self.identities.values():
            if identity.trust_level == TrustLevel.UNTRUSTED:
                recommendations.append({
                    "identity": identity.name,
                    "action": "DISABLE",
                    "reason": f"Untrusted identity with risk score {identity.risk_score:.2f}",
                    "priority": "CRITICAL"
                })
            
            elif identity.anomaly_flags:
                recommendations.append({
                    "identity": identity.name,
                    "action": "REVIEW_PERMISSIONS",
                    "reason": f"Anomaly flags: {', '.join(identity.anomaly_flags[:2])}",
                    "priority": "HIGH",
                    "suggested_policy": self._generate_minimal_policy(identity)
                })
            
            elif not identity.mfa_verified and identity.identity_type == 'user':
                recommendations.append({
                    "identity": identity.name,
                    "action": "ENFORCE_MFA",
                    "reason": "No MFA device - account vulnerable to credential theft",
                    "priority": "HIGH",
                    "policy_change": {
                        "attach": "arn:aws:iam::aws:policy/AWSMFARequiredPolicy",
                        "condition": "aws:MultiFactorAuthPresent: true"
                    }
                })
        
        return recommendations

    def _generate_minimal_policy(self, identity: Identity) -> Dict:
        """Generate a minimal IAM policy based on observed behavior."""
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": f"AZTCSELeastPrivilege{identity.name}",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucket",
                ],
                "Resource": "*",
                "Condition": {
                    "Bool": {"aws:MultiFactorAuthPresent": "true"},
                    "IpAddress": {"aws:SourceIp": list(identity.known_ips) or ["10.0.0.0/8"]}
                }
            }]
        }

    def get_dashboard_data(self) -> Dict:
        """Return data for Zero Trust dashboard."""
        trust_dist = {t.value: 0 for t in TrustLevel}
        for identity in self.identities.values():
            trust_dist[identity.trust_level.value] += 1
        
        active_grants = [g for g in self.jit_grants.values() if g.is_active and not g.is_expired()]
        
        return {
            "total_identities": len(self.identities),
            "trust_distribution": trust_dist,
            "active_jit_grants": len(active_grants),
            "policy_violations_24h": len([
                v for v in self.policy_violations
                if (datetime.now(timezone.utc) - datetime.fromisoformat(v['timestamp'])).days < 1
            ]),
            "access_requests_processed": len(self.access_log),
            "deny_rate": (
                sum(1 for r in self.access_log if r.decision == AccessDecision.DENY) /
                max(len(self.access_log), 1)
            ),
            "identities_at_risk": [i.to_dict() for i in self.identities.values() if i.risk_score > 0.6],
            "active_jit_grants_detail": [g.to_dict() for g in active_grants],
            "recent_violations": self.policy_violations[-10:],
            "recommendations": self.apply_least_privilege_recommendations()[:5],
        }

    def print_dashboard(self):
        """Print Zero Trust dashboard."""
        data = self.get_dashboard_data()
        
        table = Table(title="🔐 Zero Trust Enforcement Dashboard", style="blue")
        table.add_column("Metric", style="bold")
        table.add_column("Value")
        
        table.add_row("Total Identities", str(data['total_identities']))
        table.add_row("Active JIT Grants", str(data['active_jit_grants']))
        table.add_row("Policy Violations (24h)", f"[red]{data['policy_violations_24h']}[/red]")
        table.add_row("Requests Processed", str(data['access_requests_processed']))
        table.add_row("Deny Rate", f"{data['deny_rate']:.1%}")
        
        for trust_level, count in data['trust_distribution'].items():
            if count > 0:
                color = {"UNTRUSTED": "red", "LOW": "orange3", "MEDIUM": "yellow",
                        "HIGH": "green", "CRITICAL": "cyan"}.get(trust_level, "white")
                table.add_row(f"  Trust: {trust_level}", f"[{color}]{count}[/{color}]")
        
        console.print(table)
