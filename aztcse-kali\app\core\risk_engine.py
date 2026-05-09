from __future__ import annotations

from app.core.attack_simulator import AttackSimulator
from app.core.models import CloudInventory, RiskFinding


class DynamicRiskScoringEngine:
    """Scores cloud risk as connected attack chains, not isolated alerts."""

    def __init__(self) -> None:
        self.simulator = AttackSimulator()

    def score(self, inventory: CloudInventory) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        findings.extend(self._resource_findings(inventory))
        findings.extend(self._attack_path_findings(inventory))
        findings.sort(key=lambda item: item.score, reverse=True)
        return findings

    def total_score(self, inventory: CloudInventory) -> float:
        findings = self.score(inventory)
        if not findings:
            return 0.0
        return round(min(100.0, sum(item.score for item in findings[:5]) / 5), 2)

    def _resource_findings(self, inventory: CloudInventory) -> list[RiskFinding]:
        findings: list[RiskFinding] = []

        for resource in inventory.resources:
            privileges = {item.lower() for item in resource.privileges}
            tags = resource.tags

            if resource.exposure.value == "public" and resource.sensitive:
                findings.append(
                    RiskFinding(
                        id=f"risk-public-sensitive-{resource.id}",
                        title="Public exposure on sensitive resource",
                        severity="critical",
                        score=95,
                        resources=[resource.id],
                        evidence=f"{resource.name} is public and marked sensitive.",
                        recommended_actions=[
                            "Remove public exposure",
                            "Apply least privilege policy",
                            "Enable continuous monitoring",
                        ],
                    )
                )

            if resource.exposure.value == "public" and (
                "admin" in privileges or "*" in privileges
            ):
                findings.append(
                    RiskFinding(
                        id=f"risk-public-admin-{resource.id}",
                        title="Public resource has administrative privilege",
                        severity="critical",
                        score=98,
                        resources=[resource.id],
                        evidence=f"{resource.name} is public and has administrative permissions.",
                        recommended_actions=[
                            "Remove administrative permission",
                            "Force just-in-time access",
                            "Rotate credentials",
                        ],
                    )
                )

            if tags.get("no_mfa"):
                findings.append(
                    RiskFinding(
                        id=f"risk-no-mfa-{resource.id}",
                        title="Identity control missing MFA",
                        severity="high",
                        score=78,
                        resources=[resource.id],
                        evidence=f"{resource.name} is tagged as no_mfa.",
                        recommended_actions=[
                            "Require MFA",
                            "Block risky sessions",
                            "Review trust policy",
                        ],
                    )
                )

            if tags.get("stale_key"):
                findings.append(
                    RiskFinding(
                        id=f"risk-stale-key-{resource.id}",
                        title="Stale cloud access key",
                        severity="high",
                        score=82,
                        resources=[resource.id],
                        evidence=f"{resource.name} has stale_key=true.",
                        recommended_actions=[
                            "Rotate access key",
                            "Disable unused key",
                            "Audit recent CloudTrail activity",
                        ],
                    )
                )

        return findings

    def _attack_path_findings(self, inventory: CloudInventory) -> list[RiskFinding]:
        findings: list[RiskFinding] = []

        for index, path in enumerate(self.simulator.simulate(inventory), start=1):
            severity = self._severity(path.score)
            findings.append(
                RiskFinding(
                    id=f"risk-attack-path-{index}",
                    title="Attack chain discovered by simulator",
                    severity=severity,
                    score=path.score,
                    resources=path.route,
                    evidence=" -> ".join(path.route),
                    recommended_actions=[
                        "Break unnecessary trust relationships",
                        "Apply least privilege",
                        "Isolate public entry point",
                        "Validate response in digital twin",
                    ],
                )
            )

        return findings

    def _severity(self, score: float) -> str:
        if score >= 90:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        return "low"
