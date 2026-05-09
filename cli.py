#!/usr/bin/env python3
"""
AZTCSE Command-Line Interface
================================
Full terminal interface for AZTCSE engine.
Supports interactive mode, automated scans, and report export.

Usage:
  python cli.py scan                    # Scan AWS infrastructure
  python cli.py analyze                 # Run full analysis pipeline
  python cli.py attack --episodes 500   # Run attack simulation
  python cli.py report --format pdf     # Export report
  python cli.py serve                   # Start web dashboard
  python cli.py demo                    # Full demo run
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

# Make sure the root is on path
sys.path.insert(0, str(Path(__file__).parent))

from config.settings import config
from modules.casg.graph_builder import CloudAttackSurfaceGraph
from modules.attack_sim.simulator import AIAttackSimulator
from modules.risk_engine.scorer import DynamicRiskEngine
from modules.response_engine.responder import AutonomousResponseEngine
from modules.zero_trust.enforcer import ZeroTrustEngine
from modules.digital_twin.twin import CloudDigitalTwin
from modules.gnn_detector.detector import GNNThreatDetector
from modules.threat_intel.intel_engine import ThreatIntelligenceEngine

app = typer.Typer(
    name="aztcse",
    help="AZTCSE — Autonomous Zero-Trust Cloud Security Engine | IIIT Nagpur",
    add_completion=False,
)
console = Console()


def print_banner():
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║         AZTCSE — Autonomous Zero-Trust Cloud Security         ║
    ║              Engine v2.0  |  IIIT Nagpur                     ║
    ║                                                               ║
    ║   Modules:  CASG · Attack Sim · Risk Engine · Auto Response  ║
    ║             Zero Trust · Digital Twin · GNN · Threat Intel   ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]")


async def _init_engines(use_demo: bool = True):
    """Initialize all engine modules."""
    casg = CloudAttackSurfaceGraph(
        neo4j_uri=config.NEO4J_URI,
        neo4j_user=config.NEO4J_USER,
        neo4j_pass=config.NEO4J_PASSWORD,
        aws_region=config.AWS_REGION
    )

    try:
        await casg.connect()
    except Exception:
        pass  # Neo4j optional

    if use_demo:
        await casg._load_demo_graph()
    else:
        await casg.scan_aws_infrastructure()

    return {
        'casg': casg,
        'attack_sim': AIAttackSimulator(casg),
        'risk_engine': DynamicRiskEngine(casg),
        'response_engine': AutonomousResponseEngine(
            aws_region=config.AWS_REGION,
            dry_run=True
        ),
        'zero_trust': ZeroTrustEngine(aws_region=config.AWS_REGION),
        'gnn': GNNThreatDetector(casg),
        'threat_intel': ThreatIntelligenceEngine(casg),
    }


@app.command("demo")
def cmd_demo(
    episodes: int = typer.Option(100, help="RL training episodes"),
    export: bool = typer.Option(False, help="Export JSON report"),
    output: str = typer.Option("aztcse_report.json", help="Output file"),
):
    """Run the full AZTCSE demo pipeline with all 8 modules."""
    print_banner()

    async def _run():
        engines = await _init_engines(use_demo=True)
        casg = engines['casg']
        report_data = {}

        # 1. Graph Summary
        console.print("\n[bold]━━━ Module 1: Cloud Attack Surface Graph ━━━[/bold]")
        casg.print_summary()
        report_data['graph'] = casg.get_graph_summary()

        # 2. Risk Analysis
        console.print("\n[bold]━━━ Module 3: Dynamic Risk Engine ━━━[/bold]")
        risk_report = await engines['risk_engine'].run_full_analysis()
        engines['risk_engine'].print_summary()
        report_data['risk'] = {
            'overall_score': risk_report['overall_risk_score'],
            'severity': risk_report['overall_severity'],
            'total_findings': risk_report['total_findings'],
            'chains': risk_report['risk_chains_detected'],
        }

        # 3. GNN Detection
        console.print("\n[bold]━━━ Module 7: GNN Threat Detector ━━━[/bold]")
        gnn_report = engines['gnn'].get_report()
        engines['gnn'].print_summary()
        report_data['gnn'] = {
            'analyzed': gnn_report['total_nodes_analyzed'],
            'novel_threats': gnn_report['novel_threats_found'],
        }

        # 4. Threat Intel
        console.print("\n[bold]━━━ Module 8: Threat Intelligence ━━━[/bold]")
        ti_report = await engines['threat_intel'].run_correlation()
        engines['threat_intel'].print_mitre_summary()
        report_data['threat_intel'] = {
            'ioc_matches': ti_report['total_ioc_matches'],
            'mitre_techniques': ti_report['mitre_techniques_mapped'],
        }

        # 5. Attack Simulation
        console.print("\n[bold]━━━ Module 2: AI Attack Simulator ━━━[/bold]")
        attack_paths = await engines['attack_sim'].run_full_simulation(n_episodes=episodes)
        stats = engines['attack_sim'].get_attack_statistics()
        report_data['attack_sim'] = stats

        # 6. Zero Trust
        console.print("\n[bold]━━━ Module 5: Zero Trust Enforcer ━━━[/bold]")
        await engines['zero_trust'].initialize_from_graph(casg)
        engines['zero_trust'].print_dashboard()
        report_data['zero_trust'] = engines['zero_trust'].get_dashboard_data()

        # 7. Response Plan
        console.print("\n[bold]━━━ Module 4: Autonomous Response Engine ━━━[/bold]")
        actions = await engines['response_engine'].generate_response_plan(
            risk_report, attack_paths
        )
        engines['response_engine'].print_action_plan()
        execute_results = await engines['response_engine'].execute_all_auto_actions()
        report_data['response'] = {
            'total_actions': len(actions),
            'executed': execute_results.get('executed', 0),
            'pending_approval': execute_results.get('pending_approval', 0),
        }

        # 8. Digital Twin
        console.print("\n[bold]━━━ Module 6: Cloud Digital Twin ━━━[/bold]")
        dt = CloudDigitalTwin(
            casg, engines['risk_engine'],
            engines['response_engine'], engines['zero_trust']
        )
        await dt.sync_from_real_cloud()
        sim_results = await dt.run_all_scenarios()
        twin_report = dt.get_twin_report()
        report_data['digital_twin'] = {
            'scenarios_run': twin_report.get('total_scenarios_run', 0),
            'attack_success_rate': twin_report.get('attack_success_rate', '0%'),
            'security_rating': twin_report.get('overall_security_rating', 'UNKNOWN'),
        }

        # Final summary
        console.print("\n")
        console.print(Panel(
            f"""
[bold white]AZTCSE Full Analysis Complete[/bold white]

[cyan]Infrastructure:[/cyan]   {report_data['graph']['total_nodes']} resources, {report_data['graph']['total_edges']} relationships
[red]Risk Score:[/red]       {report_data['risk']['overall_score']:.0%} ({report_data['risk']['severity']})
[orange3]Findings:[/orange3]         {report_data['risk']['total_findings']} total, {report_data['risk']['chains']} risk chains
[yellow]Attack Paths:[/yellow]     {report_data['attack_sim'].get('total_paths_found', 0)} found
[magenta]GNN Threats:[/magenta]      {report_data['gnn']['novel_threats']} novel (missed by rules)
[blue]MITRE Hits:[/blue]       {report_data['threat_intel']['mitre_techniques']} techniques
[green]Auto-Remediated:[/green]  {report_data['response']['executed']} actions
[cyan]Twin Security:[/cyan]    {report_data['digital_twin']['security_rating']}
            """,
            title="[bold cyan]📊 AZTCSE Summary Report[/bold cyan]",
            border_style="cyan",
        ))

        if export:
            with open(output, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            console.print(f"\n[green]✓ Report exported to {output}[/green]")

        await casg.close()

    asyncio.run(_run())


@app.command("scan")
def cmd_scan(
    demo: bool = typer.Option(False, help="Use demo data (no AWS required)"),
    region: str = typer.Option("us-east-1", help="AWS region"),
):
    """Scan cloud infrastructure and build attack surface graph."""
    print_banner()

    async def _run():
        casg = CloudAttackSurfaceGraph(
            neo4j_uri=config.NEO4J_URI,
            neo4j_user=config.NEO4J_USER,
            neo4j_pass=config.NEO4J_PASSWORD,
            aws_region=region
        )
        try:
            await casg.connect()
        except Exception:
            pass

        if demo:
            await casg._load_demo_graph()
        else:
            await casg.scan_aws_infrastructure()

        casg.print_summary()

        # Show high-risk nodes
        high_risk = casg.get_high_risk_nodes(threshold=0.6)
        if high_risk:
            table = Table(title="⚠️ High-Risk Resources", style="red")
            table.add_column("Name")
            table.add_column("Type")
            table.add_column("Risk Score", justify="right")
            table.add_column("Misconfigurations")
            for node in sorted(high_risk, key=lambda x: -x.risk_score):
                table.add_row(
                    node.name,
                    node.node_type.value,
                    f"[red]{node.risk_score:.0%}[/red]",
                    str(len(node.misconfigurations))
                )
            console.print(table)

        await casg.close()

    asyncio.run(_run())


@app.command("analyze")
def cmd_analyze(
    export: str = typer.Option(None, help="Export to JSON file"),
):
    """Run dynamic risk analysis and GNN threat detection."""
    print_banner()

    async def _run():
        engines = await _init_engines(use_demo=False)
        risk_report = await engines['risk_engine'].run_full_analysis()
        engines['risk_engine'].print_summary()

        gnn_report = engines['gnn'].get_report()
        engines['gnn'].print_summary()

        ti_report = await engines['threat_intel'].run_correlation()
        engines['threat_intel'].print_mitre_summary()

        if export:
            with open(export, 'w') as f:
                json.dump({
                    'risk': risk_report,
                    'gnn': gnn_report,
                    'threat_intel': ti_report,
                }, f, indent=2, default=str)
            console.print(f"[green]✓ Exported to {export}[/green]")

        await engines['casg'].close()

    asyncio.run(_run())


@app.command("attack")
def cmd_attack(
    episodes: int = typer.Option(200, help="RL training episodes"),
    show_paths: int = typer.Option(10, help="Number of paths to display"),
):
    """Run AI-powered attack simulation."""
    print_banner()

    async def _run():
        engines = await _init_engines(use_demo=False)
        paths = await engines['attack_sim'].run_full_simulation(n_episodes=episodes)
        stats = engines['attack_sim'].get_attack_statistics()

        table = Table(title="🔴 Top Attack Paths", style="red")
        table.add_column("ID")
        table.add_column("Objective")
        table.add_column("Steps", justify="right")
        table.add_column("Success Prob", justify="right")
        table.add_column("Criticality")

        colors = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}
        for path in paths[:show_paths]:
            c = colors.get(path.criticality, "white")
            table.add_row(
                path.path_id,
                path.objective.replace("_", " "),
                str(len(path.steps)),
                f"[{c}]{path.overall_success_prob:.1%}[/{c}]",
                f"[{c}]{path.criticality}[/{c}]",
            )
        console.print(table)

        console.print(f"\n[bold]Statistics:[/bold]")
        console.print(f"  Total paths: {stats.get('total_paths_found', 0)}")
        console.print(f"  Avg success probability: {stats.get('avg_success_probability', 0):.1%}")
        console.print(f"  Critical paths: {stats.get('criticality_distribution', {}).get('CRITICAL', 0)}")

        await engines['casg'].close()

    asyncio.run(_run())


@app.command("serve")
def cmd_serve(
    host: str = typer.Option("0.0.0.0", help="Bind host"),
    port: int = typer.Option(8000, help="Port"),
    reload: bool = typer.Option(False, help="Auto-reload"),
):
    """Start the AZTCSE web dashboard."""
    import uvicorn
    print_banner()
    console.print(f"[green]Starting AZTCSE API server on http://{host}:{port}[/green]")
    console.print(f"[cyan]Dashboard: http://localhost:{port}/dashboard[/cyan]")
    console.print(f"[cyan]API Docs:  http://localhost:{port}/docs[/cyan]")
    uvicorn.run(
        "api.main:app",
        host=host,
        port=port,
        reload=reload,
    )


@app.command("zerotrust")
def cmd_zerotrust(
    identity: str = typer.Option(None, help="Identity ID to evaluate"),
    resource: str = typer.Option(None, help="Resource ARN"),
    action: str = typer.Option("s3:GetObject", help="AWS action"),
):
    """Evaluate access using Zero Trust policy engine."""
    print_banner()

    async def _run():
        engines = await _init_engines(use_demo=False)
        zt = engines['zero_trust']
        await zt.initialize_from_graph(engines['casg'])

        if identity and resource:
            from modules.zero_trust.enforcer import AccessRequest
            req = AccessRequest(
                identity_id=identity,
                resource_arn=resource,
                action=action
            )
            decision = await zt.evaluate_access(req)
            color = {"ALLOW": "green", "DENY": "red",
                     "CHALLENGE": "yellow", "STEP_UP": "orange3"}.get(decision.value, "white")
            console.print(
                f"\n[bold]Access Decision:[/bold] [{color}]{decision.value}[/{color}]"
            )
            console.print(f"[dim]Reason: {req.reason}[/dim]")
        else:
            zt.print_dashboard()

        await engines['casg'].close()

    asyncio.run(_run())






@app.command("honeypot")
def cmd_honeypot(
    deploy: bool = typer.Option(True, help="Deploy honeypot resources"),
    monitor: bool = typer.Option(True, help="Monitor for access attempts"),
    cleanup: bool = typer.Option(False, help="Remove honeypot resources"),
):
    """Module 9: Deploy honeypot decoys and detect attackers on your AWS account."""
    from modules.honeypot.honeypot import run_honeypot

    async def _run():
        account_id = os.getenv("AWS_ACCOUNT_ID", "710215922764")
        region = os.getenv("AWS_REGION", "ap-south-1")
        await run_honeypot(account_id=account_id, region=region,
                          deploy=deploy, monitor=monitor, cleanup=cleanup)

    asyncio.run(_run())




@app.command("forensic")
def cmd_forensic(
    hours: int = typer.Option(72, help="Hours of logs to analyze"),
):
    """Module 10: Forensic investigation — analyze CloudTrail for suspicious activity."""
    from modules.forensic import run_forensic_investigation

    async def _run():
        account_id = os.getenv("AWS_ACCOUNT_ID", "710215922764")
        region = os.getenv("AWS_REGION", "ap-south-1")
        await run_forensic_investigation(account_id=account_id, region=region, hours=hours)

    asyncio.run(_run())

@app.command("attack2")
def cmd_attack2(
    region: str = typer.Option("us-east-1", help="AWS region"),
):
    """Module 11: Advanced attack simulation with AWS validation."""
    from modules.attack_sim.advanced_attack_sim import run_advanced_attack_simulation

    async def _run():
        casg = CloudAttackSurfaceGraph(
            neo4j_uri=config.NEO4J_URI,
            neo4j_user=config.NEO4J_USER,
            neo4j_pass=config.NEO4J_PASSWORD,
            aws_region=region
        )
        try:
            await casg.connect()
        except Exception:
            pass
        await casg.scan_aws_infrastructure()
        account_id = os.getenv("AWS_ACCOUNT_ID", "710215922764")
        await run_advanced_attack_simulation(casg=casg, account_id=account_id, region=region)
        await casg.close()

    asyncio.run(_run())


@app.command("attack3")
def cmd_attack3(
    region: str = typer.Option("us-east-1", help="AWS region"),
    personas: str = typer.Option(
        "all",
        help="Comma-separated personas: nation_state,ransomware,insider,script_kiddie,supply_chain or 'all'"
    ),
):
    """Module 12: Extended attacker simulation — 5 attacker personas with kill chains."""
    from modules.attack_sim.attacker_sim_extended import (
        run_extended_attack_simulation, AttackerPersona
    )
    import asyncio, os

    persona_map = {
        "nation_state":  AttackerPersona.NATION_STATE,
        "ransomware":    AttackerPersona.RANSOMWARE,
        "insider":       AttackerPersona.INSIDER,
        "script_kiddie": AttackerPersona.SCRIPT_KIDDIE,
        "supply_chain":  AttackerPersona.SUPPLY_CHAIN,
    }

    if personas.strip().lower() == "all":
        selected = list(AttackerPersona)
    else:
        selected = [persona_map[p.strip().lower()] for p in personas.split(",") if p.strip().lower() in persona_map]

    account_id = os.getenv("AWS_ACCOUNT_ID", "")
    asyncio.run(run_extended_attack_simulation(
        account_id=account_id,
        region=region,
        personas=selected,
        export_json=True,
    ))


@app.command("report")
def cmd_report(
    region: str      = typer.Option("us-east-1",          help="AWS region"),
    client: str      = typer.Option("Assessment Target",   help="Client/target name"),
    assessor: str    = typer.Option("AZTCSE Engine",       help="Assessor name"),
    json_files: str  = typer.Option("",                    help="Comma-separated attack JSON files (auto-discover if empty)"),
    out_dir: str     = typer.Option(".",                   help="Output directory"),
):
    """Module 13: Generate professional post-exploitation PDF/HTML report."""
    import os
    from modules.reporting.report_generator import generate_report

    account_id = os.getenv("AWS_ACCOUNT_ID", "")
    files = [f.strip() for f in json_files.split(",") if f.strip()] if json_files else None

    output_path = generate_report(
        account_id=account_id,
        region=region,
        client_name=client,
        assessor=assessor,
        attack_json_files=files,
        output_dir=out_dir,
    )
    typer.echo(f"\nReport saved: {output_path}")


@app.command("scope")
def cmd_scope(
    region: str    = typer.Option("us-east-1",          help="AWS region"),
    client: str    = typer.Option("CLIENT NAME",         help="Client/target organisation name"),
    assessor: str  = typer.Option("AZTCSE Engine",       help="Assessor or firm name"),
    start: str     = typer.Option("",                    help="Assessment start date YYYY-MM-DD"),
    end: str       = typer.Option("",                    help="Assessment end date YYYY-MM-DD"),
    out_dir: str   = typer.Option(".",                   help="Output directory"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Prompt for key fields"),
):
    """Module 14: Generate pentest scope document (RoE, SoW, test plan, auth letter)."""
    import os
    from modules.pentest_scope.scope_generator import generate_scope_document

    account_id = os.getenv("AWS_ACCOUNT_ID", "")
    md_path, html_path = generate_scope_document(
        account_id=account_id,
        region=region,
        client_name=client,
        assessor_name=assessor,
        start_date=start,
        end_date=end,
        output_dir=out_dir,
        auto_discover=True,
        interactive=interactive,
    )
    typer.echo(f"\nMarkdown: {md_path}")
    typer.echo(f"HTML:     {html_path}")

if __name__ == "__main__":
    app()
