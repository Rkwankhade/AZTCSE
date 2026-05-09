from __future__ import annotations

from app.core.models import CloudInventory, ZeroTrustPolicy


class ZeroTrustEnforcementLayer:
    """Continuously recommends least privilege and just-in-time controls."""

    def generate(self, inventory: CloudInventory) -> list[ZeroTrustPolicy]:
        policies: list[ZeroTrustPolicy] = []

        for resource in inventory.resources:
            controls = [
                "deny by default",
                "verify identity every request",
                "log every privileged action",
            ]

            if resource.exposure.value == "public":
                controls.append("block public access unless explicitly approved")
            if resource.sensitive:
                controls.append("require just-in-time approval for sensitive access")
            if resource.privileges:
                controls.append("replace static broad privilege with scoped permissions")
            if resource.tags.get("no_mfa"):
                controls.append("enforce MFA before session creation")

            policies.append(
                ZeroTrustPolicy(
                    resource_id=resource.id,
                    policy_name=f"aztcse-zero-trust-{resource.id}",
                    controls=controls,
                    just_in_time_access=True,
                    least_privilege=True,
                )
            )

        return policies
