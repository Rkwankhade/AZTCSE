from __future__ import annotations

import json
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from app.core.attack_simulator import AttackSimulator
from app.core.attack_surface_graph import CloudAttackSurfaceGraph
from app.core.digital_twin import CloudDigitalTwin
from app.core.models import CloudInventory
from app.core.response_engine import AutonomousResponseEngine
from app.core.risk_engine import DynamicRiskScoringEngine
from app.core.zero_trust import ZeroTrustEnforcementLayer

cli = typer.Typer(help="Autonomous Zero-Trust Cloud Security Engine CLI")
console = Console()
load_dotenv()


def load_inventory(path: Path) -> CloudInventory:
    return CloudInventory.model_validate_json(path.read_text(encoding="utf-8"))


@cli.command()
def graph(inventory_file: Path) -> None:
    inventory = load_inventory(inventory_file)
    payload = CloudAttackSurfaceGraph().graph_payload(inventory)
    console.print_json(json.dumps(payload))


@cli.command()
def simulate(inventory_file: Path) -> None:
    inventory = load_inventory(inventory_file)
    paths = AttackSimulator().simulate(inventory)
    table = Table(title="AI-Powered Attack Simulator")
    table.add_column("Score")
    table.add_column("Start")
    table.add_column("Target")
    table.add_column("Route")
    table.add_column("Techniques")

    for path in paths:
        table.add_row(
            f"{path.score:.1f}",
            path.start,
            path.target,
            " -> ".join(path.route),
            ", ".join(path.techniques),
        )

    console.print(table)


@cli.command()
def risk(inventory_file: Path) -> None:
    inventory = load_inventory(inventory_file)
    engine = DynamicRiskScoringEngine()
    findings = engine.score(inventory)
    table = Table(title=f"Dynamic Risk Score: {engine.total_score(inventory)}")
    table.add_column("Severity")
    table.add_column("Score")
    table.add_column("Finding")
    table.add_column("Evidence")

    for finding in findings:
        table.add_row(
            finding.severity,
            f"{finding.score:.1f}",
            finding.title,
            finding.evidence,
        )

    console.print(table)


@cli.command()
def respond(inventory_file: Path) -> None:
    inventory = load_inventory(inventory_file)
    actions = AutonomousResponseEngine().plan(inventory)
    table = Table(title="Autonomous Response Engine")
    table.add_column("Operation")
    table.add_column("Resource")
    table.add_column("Dry Run")
    table.add_column("Command")

    for action in actions:
        table.add_row(
            action.operation,
            action.resource_id,
            str(action.dry_run),
            action.command,
        )

    console.print(table)


@cli.command("zero-trust")
def zero_trust(inventory_file: Path) -> None:
    inventory = load_inventory(inventory_file)
    policies = ZeroTrustEnforcementLayer().generate(inventory)
    console.print_json(json.dumps([policy.model_dump() for policy in policies]))


@cli.command()
def twin(
    inventory_file: Path,
    scenario: str = typer.Option("isolate-public", "--scenario", "-s"),
) -> None:
    inventory = load_inventory(inventory_file)
    result = CloudDigitalTwin().run(inventory, scenario)
    console.print_json(result.model_dump_json())


@cli.command("full-cycle")
def full_cycle(inventory_file: Path) -> None:
    inventory = load_inventory(inventory_file)
    console.rule("Cloud Attack Surface Graph")
    graph(inventory_file)
    console.rule("Attack Simulation")
    simulate(inventory_file)
    console.rule("Risk Scoring")
    risk(inventory_file)
    console.rule("Autonomous Response")
    respond(inventory_file)
    console.rule("Digital Twin")
    twin(inventory_file, "isolate-public")


if __name__ == "__main__":
    cli()
