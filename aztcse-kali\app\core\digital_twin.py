from __future__ import annotations

from copy import deepcopy

from app.core.models import CloudInventory, DigitalTwinResult, Exposure
from app.core.risk_engine import DynamicRiskScoringEngine


class CloudDigitalTwin:
    """Runs safe what-if scenarios on a simulated clone of the cloud."""

    def __init__(self) -> None:
        self.risk_engine = DynamicRiskScoringEngine()

    def run(self, inventory: CloudInventory, scenario: str) -> DigitalTwinResult:
        before = self.risk_engine.total_score(inventory)
        clone = deepcopy(inventory)
        changed_resources: list[str] = []

        if scenario == "isolate-public":
            for resource in clone.resources:
                if resource.exposure == Exposure.public:
                    resource.exposure = Exposure.internal
                    changed_resources.append(resource.id)

        elif scenario == "remove-admin":
            for resource in clone.resources:
                original = list(resource.privileges)
                resource.privileges = [
                    privilege
                    for privilege in resource.privileges
                    if privilege.lower() not in {"admin", "*"}
                ]
                if original != resource.privileges:
                    changed_resources.append(resource.id)

        elif scenario == "enforce-mfa":
            for resource in clone.resources:
                if resource.tags.get("no_mfa"):
                    resource.tags["no_mfa"] = False
                    changed_resources.append(resource.id)

        else:
            raise ValueError(
                "Unknown scenario. Use isolate-public, remove-admin, or enforce-mfa."
            )

        after = self.risk_engine.total_score(clone)
        summary = (
            f"Scenario {scenario} reduced risk from {before} to {after}."
            if after <= before
            else f"Scenario {scenario} increased risk from {before} to {after}."
        )

        return DigitalTwinResult(
            scenario=scenario,
            before_score=before,
            after_score=after,
            changed_resources=changed_resources,
            summary=summary,
        )
