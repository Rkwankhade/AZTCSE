from __future__ import annotations

import os

from app.core.models import CloudInventory, ResponseAction, RiskFinding
from app.core.risk_engine import DynamicRiskScoringEngine


class AutonomousResponseEngine:
    """Creates autonomous response actions while remaining dry-run by default."""

    def __init__(self) -> None:
        self.risk_engine = DynamicRiskScoringEngine()
        self.dry_run = os.getenv("AZTCSE_DRY_RUN", "true").lower() != "false"

    def plan(self, inventory: CloudInventory) -> list[ResponseAction]:
        findings = self.risk_engine.score(inventory)
        actions: list[ResponseAction] = []

        for finding in findings:
            actions.extend(self._actions_for_finding(finding))

        deduped: dict[str, ResponseAction] = {}
        for action in actions:
            deduped[action.action_id] = action

        return list(deduped.values())

    def _actions_for_finding(self, finding: RiskFinding) -> list[ResponseAction]:
        actions: list[ResponseAction] = []
        first_resource = finding.resources[0] if finding.resources else "unknown"

        if "Public" in finding.title or "public" in finding.evidence.lower():
            actions.append(
                ResponseAction(
                    action_id=f"isolate-{first_resource}",
                    service="aws-ec2",
                    resource_id=first_resource,
                    operation="isolate-public-entry",
                    command=(
                        "aws ec2 revoke-security-group-ingress "
                        "--group-id <security-group-id> --protocol tcp --port 0-65535 "
                        "--cidr 0.0.0.0/0"
                    ),
                    reason="Remove broad public ingress from exposed cloud resource.",
                    dry_run=self.dry_run,
                )
            )

        if "administrative" in finding.evidence.lower() or "admin" in finding.evidence.lower():
            actions.append(
                ResponseAction(
                    action_id=f"least-privilege-{first_resource}",
                    service="aws-iam",
                    resource_id=first_resource,
                    operation="apply-least-privilege",
                    command=(
                        "aws iam put-role-policy --role-name <role-name> "
                        "--policy-name AZTCSELeastPrivilege "
                        "--policy-document file://policies/least-privilege.json"
                    ),
                    reason="Replace excessive permissions with least-privilege access.",
                    dry_run=self.dry_run,
                )
            )

        if "stale" in finding.title.lower() or "key" in finding.title.lower():
            actions.append(
                ResponseAction(
                    action_id=f"rotate-key-{first_resource}",
                    service="aws-iam",
                    resource_id=first_resource,
                    operation="rotate-key",
                    command=(
                        "aws iam update-access-key --user-name <user-name> "
                        "--access-key-id <access-key-id> --status Inactive"
                    ),
                    reason="Disable stale access key before issuing a new controlled key.",
                    dry_run=self.dry_run,
                )
            )

        if "mfa" in finding.title.lower() or "identity" in finding.title.lower():
            actions.append(
                ResponseAction(
                    action_id=f"enforce-mfa-{first_resource}",
                    service="aws-iam",
                    resource_id=first_resource,
                    operation="enforce-mfa",
                    command=(
                        "aws iam update-assume-role-policy --role-name <role-name> "
                        "--policy-document file://policies/require-mfa-trust-policy.json"
                    ),
                    reason="Require MFA before trusting identity-based access.",
                    dry_run=self.dry_run,
                )
            )

        if "Attack chain" in finding.title:
            actions.append(
                ResponseAction(
                    action_id=f"break-chain-{first_resource}",
                    service="aztcse",
                    resource_id=first_resource,
                    operation="break-attack-chain",
                    command=(
                        "python -m scripts.aztcse_cli twin samples/cloud_inventory.json "
                        "--scenario isolate-public"
                    ),
                    reason="Validate attack-chain reduction in the cloud digital twin.",
                    dry_run=True,
                )
            )

        return actions
