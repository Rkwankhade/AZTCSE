from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Exposure(str, Enum):
    private = "private"
    internal = "internal"
    public = "public"


class CloudResource(BaseModel):
    id: str
    name: str
    type: str
    provider: str = "aws"
    exposure: Exposure = Exposure.private
    privileges: list[str] = Field(default_factory=list)
    sensitive: bool = False
    tags: dict[str, Any] = Field(default_factory=dict)


class TrustRelationship(BaseModel):
    source: str
    target: str
    kind: str
    permissions: list[str] = Field(default_factory=list)
    condition: dict[str, Any] = Field(default_factory=dict)


class CloudInventory(BaseModel):
    project_name: str = "Autonomous Zero-Trust Cloud Security Engine"
    resources: list[CloudResource]
    relationships: list[TrustRelationship] = Field(default_factory=list)


class AttackPath(BaseModel):
    start: str
    target: str
    route: list[str]
    techniques: list[str]
    impact: str
    confidence: float = Field(ge=0.0, le=1.0)
    score: float = Field(ge=0.0, le=100.0)


class RiskFinding(BaseModel):
    id: str
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    score: float = Field(ge=0.0, le=100.0)
    resources: list[str]
    evidence: str
    recommended_actions: list[str]


class ResponseAction(BaseModel):
    action_id: str
    service: str
    resource_id: str
    operation: str
    command: str
    reason: str
    dry_run: bool = True
    status: Literal["planned", "executed", "skipped"] = "planned"


class ZeroTrustPolicy(BaseModel):
    resource_id: str
    policy_name: str
    controls: list[str]
    just_in_time_access: bool = True
    least_privilege: bool = True


class DigitalTwinResult(BaseModel):
    scenario: str
    before_score: float
    after_score: float
    changed_resources: list[str]
    summary: str
