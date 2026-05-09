from pathlib import Path

from app.core.attack_simulator import AttackSimulator
from app.core.digital_twin import CloudDigitalTwin
from app.core.models import CloudInventory
from app.core.response_engine import AutonomousResponseEngine
from app.core.risk_engine import DynamicRiskScoringEngine


def load_sample() -> CloudInventory:
    path = Path("samples/cloud_inventory.json")
    return CloudInventory.model_validate_json(path.read_text(encoding="utf-8"))


def test_engine_finds_attack_paths() -> None:
    inventory = load_sample()
    paths = AttackSimulator().simulate(inventory)
    assert paths
    assert paths[0].score > 0


def test_risk_engine_scores_inventory() -> None:
    inventory = load_sample()
    score = DynamicRiskScoringEngine().total_score(inventory)
    assert score > 0


def test_response_engine_generates_dry_run_actions() -> None:
    inventory = load_sample()
    actions = AutonomousResponseEngine().plan(inventory)
    assert actions
    assert all(action.dry_run for action in actions)


def test_digital_twin_reduces_or_preserves_risk() -> None:
    inventory = load_sample()
    result = CloudDigitalTwin().run(inventory, "isolate-public")
    assert result.after_score <= result.before_score
