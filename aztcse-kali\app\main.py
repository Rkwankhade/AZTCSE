from __future__ import annotations

from fastapi import FastAPI, HTTPException
from dotenv import load_dotenv
from pydantic import BaseModel

from app.core.attack_simulator import AttackSimulator
from app.core.attack_surface_graph import CloudAttackSurfaceGraph
from app.core.digital_twin import CloudDigitalTwin
from app.core.models import CloudInventory
from app.core.response_engine import AutonomousResponseEngine
from app.core.risk_engine import DynamicRiskScoringEngine
from app.core.zero_trust import ZeroTrustEnforcementLayer

load_dotenv()

app = FastAPI(
    title="Autonomous Zero-Trust Cloud Security Engine",
    version="1.0.0",
    description="Predictive and autonomous defensive cloud-security prototype.",
)

casg = CloudAttackSurfaceGraph()
simulator = AttackSimulator()
risk_engine = DynamicRiskScoringEngine()
response_engine = AutonomousResponseEngine()
zero_trust = ZeroTrustEnforcementLayer()
digital_twin = CloudDigitalTwin()


class TwinRequest(BaseModel):
    inventory: CloudInventory
    scenario: str = "isolate-public"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "engine": "AZTCSE"}


@app.post("/graph")
def graph(inventory: CloudInventory) -> dict:
    return casg.graph_payload(inventory)


@app.post("/simulate")
def simulate(inventory: CloudInventory) -> dict:
    return {"attack_paths": simulator.simulate(inventory)}


@app.post("/risk")
def risk(inventory: CloudInventory) -> dict:
    return {
        "total_score": risk_engine.total_score(inventory),
        "findings": risk_engine.score(inventory),
    }


@app.post("/respond")
def respond(inventory: CloudInventory) -> dict:
    return {"actions": response_engine.plan(inventory)}


@app.post("/zero-trust/policies")
def zero_trust_policies(inventory: CloudInventory) -> dict:
    return {"policies": zero_trust.generate(inventory)}


@app.post("/digital-twin")
def twin(request: TwinRequest) -> dict:
    try:
        return {"result": digital_twin.run(request.inventory, request.scenario)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/full-cycle")
def full_cycle(inventory: CloudInventory) -> dict:
    return {
        "graph": casg.graph_payload(inventory),
        "attack_paths": simulator.simulate(inventory),
        "risk": {
            "total_score": risk_engine.total_score(inventory),
            "findings": risk_engine.score(inventory),
        },
        "response_actions": response_engine.plan(inventory),
        "zero_trust_policies": zero_trust.generate(inventory),
        "digital_twin": digital_twin.run(inventory, "isolate-public"),
    }
