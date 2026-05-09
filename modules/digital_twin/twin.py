"""
Module 6: Cloud Digital Twin
==============================
Creates a SIMULATED CLONE of your cloud infrastructure.
- Test attacks safely
- Validate defense strategies
- Run "what-if" scenarios
- This is research-grade work.

The twin mirrors the real cloud but runs entirely in simulation.
"""

import asyncio
import copy
import json
import logging
import random
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

import networkx as nx
from rich.console import Console
from rich.table import Table

console = Console()
logger = logging.getLogger(__name__)


class SimulationEventType(str, Enum):
    ATTACK_ATTEMPT = "attack_attempt"
    DEFENSE_TRIGGERED = "defense_triggered"
    RESOURCE_MODIFIED = "resource_modified"
    POLICY_CHANGE = "policy_change"
    ANOMALY_DETECTED = "anomaly_detected"
    EXFILTRATION = "exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"


@dataclass
class SimulationEvent:
    event_id: str
    event_type: SimulationEventType
    timestamp: datetime
    source: str
    target: str
    details: Dict[str, Any]
    outcome: str  # "success" or "blocked"

    def to_dict(self) -> Dict:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "target": self.target,
            "details": self.details,
            "outcome": self.outcome,
        }


@dataclass
class SimulationScenario:
    """A what-if scenario to simulate."""
    scenario_id: str
    name: str
    description: str
    attack_sequence: List[Dict[str, Any]]  # sequence of actions to simulate
    expected_defenses: List[str]           # defenses expected to trigger
    success_criteria: str

    def to_dict(self) -> Dict:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "description": self.description,
            "step_count": len(self.attack_sequence),
            "success_criteria": self.success_criteria,
        }


@dataclass
class SimulationResult:
    """Results of a simulation run."""
    scenario: SimulationScenario
    events: List[SimulationEvent] = field(default_factory=list)
    defenses_triggered: List[str] = field(default_factory=list)
    attack_succeeded: bool = False
    data_exfiltrated: float = 0.0
    nodes_compromised: List[str] = field(default_factory=list)
    detection_time_seconds: Optional[float] = None
    total_time_seconds: float = 0.0
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "scenario": self.scenario.to_dict(),
            "total_events": len(self.events),
            "attack_succeeded": self.attack_succeeded,
            "data_exfiltrated_pct": f"{self.data_exfiltrated:.1%}",
            "nodes_compromised": self.nodes_compromised,
            "defenses_triggered": self.defenses_triggered,
            "detection_time_seconds": self.detection_time_seconds,
            "total_simulation_time_seconds": round(self.total_time_seconds, 2),
            "recommendations": self.recommendations,
        }


class CloudDigitalTwin:
    """
    Digital Twin of cloud infrastructure.
    
    Creates a complete in-memory simulation of the cloud environment
    and runs attack/defense scenarios against it safely.
    
    Use cases:
    1. Test if a new defense actually works before deploying to prod
    2. Simulate "what happens if admin credentials leak"
    3. Train the RL attacker in a realistic environment
    4. Validate incident response playbooks
    """

    def __init__(self, casg, risk_engine, response_engine, zero_trust):
        self.casg = casg
        self.risk_engine = risk_engine
        self.response_engine = response_engine
        self.zero_trust = zero_trust
        
        # The twin is a deep copy of the real infrastructure state
        self.twin_graph = None
        self.twin_nodes = {}
        self.twin_state: Dict[str, Any] = {}
        
        self.simulation_history: List[SimulationResult] = []
        self.event_log: List[SimulationEvent] = []
        self._event_counter = 0

    def _next_event_id(self) -> str:
        self._event_counter += 1
        return f"EVT-{self._event_counter:06d}"

    async def sync_from_real_cloud(self):
        """Synchronize the digital twin with real cloud state."""
        console.print("[cyan]🔄 Syncing Digital Twin with cloud state...[/cyan]")
        
        # Deep copy the real infrastructure
        self.twin_graph = copy.deepcopy(self.casg.nx_graph)
        self.twin_nodes = copy.deepcopy(self.casg.nodes)
        
        # Initialize twin state
        self.twin_state = {
            "node_states": {
                node_id: {
                    "compromised": False,
                    "isolated": False,
                    "data_exfiltrated": 0.0,
                    "active_sessions": 0,
                    "defense_level": 1.0 - node.risk_score,
                }
                for node_id, node in self.twin_nodes.items()
            },
            "network_state": {
                "active_connections": [],
                "blocked_ips": set(),
            },
            "alerts_triggered": [],
            "defenses_active": True,
        }
        
        console.print(
            f"[green]✓ Digital Twin synced: {len(self.twin_nodes)} nodes replicated[/green]"
        )

    async def run_scenario(self, scenario: SimulationScenario) -> SimulationResult:
        """
        Run a complete attack/defense scenario in the twin.
        """
        console.print(f"\n[bold magenta]🎮 Running Scenario: {scenario.name}[/bold magenta]")
        console.print(f"   {scenario.description}")
        
        # Create isolated simulation state
        sim_state = copy.deepcopy(self.twin_state)
        result = SimulationResult(scenario=scenario)
        start_time = time.time()
        
        for step_idx, step in enumerate(scenario.attack_sequence):
            event = await self._simulate_step(step, sim_state, result)
            result.events.append(event)
            
            # Check if defense blocks the attack
            if event.outcome == "blocked":
                if scenario.success_criteria == "all_steps_succeed":
                    console.print(f"  [green]Step {step_idx+1} BLOCKED by defense[/green]")
                    break
            else:
                console.print(f"  [red]Step {step_idx+1} SUCCEEDED: {step.get('description', '')}[/red]")
                
                # Update compromised state
                target = step.get('target', '')
                if target in sim_state['node_states']:
                    sim_state['node_states'][target]['compromised'] = True
                    result.nodes_compromised.append(target)
                
                # Check for data exfiltration
                if step.get('type') == 'exfiltration':
                    exfil_amount = step.get('data_amount', 0.3)
                    result.data_exfiltrated += exfil_amount
                    sim_state['node_states'][target]['data_exfiltrated'] += exfil_amount
            
            # Check defenses response
            defense_response = await self._check_defenses(event, sim_state)
            if defense_response:
                result.defenses_triggered.extend(defense_response)
                if not result.detection_time_seconds:
                    result.detection_time_seconds = time.time() - start_time
        
        # Evaluate outcome
        result.attack_succeeded = (
            len(result.nodes_compromised) > 0 or result.data_exfiltrated > 0
        )
        result.total_time_seconds = time.time() - start_time
        
        # Generate recommendations
        result.recommendations = self._generate_scenario_recommendations(result)
        
        self.simulation_history.append(result)
        
        # Print summary
        color = "[red]" if result.attack_succeeded else "[green]"
        outcome = "SUCCEEDED" if result.attack_succeeded else "BLOCKED"
        console.print(f"\n  {color}Scenario Outcome: {outcome}[/]")
        console.print(f"  Nodes compromised: {len(result.nodes_compromised)}")
        console.print(f"  Data exfiltrated: {result.data_exfiltrated:.1%}")
        console.print(f"  Defenses triggered: {len(result.defenses_triggered)}")
        if result.detection_time_seconds:
            console.print(f"  Detection time: {result.detection_time_seconds:.1f}s")
        
        return result

    async def _simulate_step(self, step: Dict, sim_state: Dict, 
                              result: SimulationResult) -> SimulationEvent:
        """Simulate a single attack step."""
        step_type = step.get('type', 'unknown')
        source = step.get('source', 'external')
        target = step.get('target', 'unknown')
        
        # Calculate success probability
        base_success = step.get('success_probability', 0.7)
        
        # Defenses reduce success probability
        target_state = sim_state['node_states'].get(target, {})
        defense_level = target_state.get('defense_level', 0.5)
        
        # Misconfigurations increase success probability
        target_node = self.twin_nodes.get(target)
        misconfiguration_bonus = 0.0
        if target_node and target_node.misconfigurations:
            misconfiguration_bonus = 0.1 * len(target_node.misconfigurations)
        
        final_success_prob = min(
            base_success * (1.0 + misconfiguration_bonus) * (1.0 - defense_level * 0.3),
            0.95
        )
        
        success = random.random() < final_success_prob
        
        event = SimulationEvent(
            event_id=self._next_event_id(),
            event_type=SimulationEventType(
                {'attack': SimulationEventType.ATTACK_ATTEMPT,
                 'lateral_movement': SimulationEventType.LATERAL_MOVEMENT,
                 'exfiltration': SimulationEventType.EXFILTRATION,
                 'privilege_escalation': SimulationEventType.PRIVILEGE_ESCALATION
                }.get(step_type, SimulationEventType.ATTACK_ATTEMPT)
            ),
            timestamp=datetime.now(timezone.utc),
            source=source,
            target=target,
            details={
                "step_type": step_type,
                "description": step.get('description', ''),
                "success_probability": final_success_prob,
                "defense_level": defense_level,
            },
            outcome="success" if success else "blocked"
        )
        
        self.event_log.append(event)
        return event

    async def _check_defenses(self, event: SimulationEvent, 
                               sim_state: Dict) -> List[str]:
        """Check if any defenses respond to the event."""
        triggered = []
        
        if event.outcome == "success":
            # AZTCSE autonomous response would trigger
            if sim_state['defenses_active']:
                if event.event_type in [SimulationEventType.EXFILTRATION, 
                                         SimulationEventType.PRIVILEGE_ESCALATION]:
                    triggered.append("AZTCSE: Autonomous response triggered")
                    triggered.append(f"AZTCSE: Isolating {event.target}")
                    
                    # Simulate defense taking effect
                    target_state = sim_state['node_states'].get(event.target, {})
                    target_state['isolated'] = True
                    target_state['defense_level'] = 1.0  # Max defense
                    sim_state['alerts_triggered'].append(event.event_id)
                
                if event.event_type == SimulationEventType.LATERAL_MOVEMENT:
                    triggered.append("Zero Trust: Access revoked after lateral movement")
                    triggered.append("CloudTrail: Alert generated")
        
        return triggered

    def _generate_scenario_recommendations(self, result: SimulationResult) -> List[str]:
        """Generate security recommendations from simulation results."""
        recs = []
        
        if result.attack_succeeded:
            recs.append(
                f"CRITICAL: Simulation showed {len(result.nodes_compromised)} nodes compromised. "
                f"Immediate hardening required."
            )
        
        if result.data_exfiltrated > 0:
            recs.append(
                f"Data exfiltration succeeded ({result.data_exfiltrated:.1%}). "
                f"Implement DLP controls and S3 bucket policies immediately."
            )
        
        if not result.detection_time_seconds:
            recs.append(
                "Attack was never detected! Enable CloudTrail and CloudWatch alerts "
                "for real-time threat detection."
            )
        elif result.detection_time_seconds > 60:
            recs.append(
                f"Detection took {result.detection_time_seconds:.0f}s - too slow. "
                f"Configure real-time CloudWatch alarms."
            )
        
        if result.nodes_compromised:
            recs.append(
                "Segment network to limit lateral movement. Use private subnets "
                "and restrict cross-service communication."
            )
        
        if not result.defenses_triggered:
            recs.append(
                "No defenses triggered during attack. Deploy AZTCSE Autonomous "
                "Response Engine to automatically respond to threats."
            )
        
        return recs

    def get_predefined_scenarios(self) -> List[SimulationScenario]:
        """Return a library of predefined attack scenarios."""
        node_ids = list(self.twin_nodes.keys())
        public_nodes = [nid for nid, n in self.twin_nodes.items() if n.is_public]
        s3_nodes = [nid for nid, n in self.twin_nodes.items() if n.node_type.value == 'S3_BUCKET']
        iam_users = [nid for nid, n in self.twin_nodes.items() if n.node_type.value == 'IAM_USER']
        iam_roles = [nid for nid, n in self.twin_nodes.items() if n.node_type.value == 'IAM_ROLE']
        
        scenarios = []
        
        # Scenario 1: Public bucket exfiltration
        if public_nodes and s3_nodes:
            pub_s3 = [n for n in public_nodes if n in s3_nodes]
            if pub_s3:
                scenarios.append(SimulationScenario(
                    scenario_id="S001",
                    name="Direct S3 Exfiltration",
                    description="Attacker discovers and exfiltrates data from public S3 bucket",
                    attack_sequence=[
                        {"type": "attack", "source": "external", "target": pub_s3[0],
                         "success_probability": 0.95, "description": "Enumerate public S3"},
                        {"type": "exfiltration", "source": pub_s3[0], "target": pub_s3[0],
                         "success_probability": 0.90, "data_amount": 0.8,
                         "description": "Download all bucket contents"},
                    ],
                    expected_defenses=["S3 Block Public Access", "CloudTrail Alert"],
                    success_criteria="any_step_blocked"
                ))
        
        # Scenario 2: Credential theft to full compromise
        if iam_users:
            scenarios.append(SimulationScenario(
                scenario_id="S002",
                name="Credential Theft → Admin Takeover",
                description="Attacker steals IAM credentials and escalates to admin",
                attack_sequence=[
                    {"type": "attack", "source": "external", "target": iam_users[0],
                     "success_probability": 0.60, "description": "Phish IAM credentials"},
                    {"type": "privilege_escalation", "source": iam_users[0],
                     "target": iam_roles[0] if iam_roles else iam_users[0],
                     "success_probability": 0.70, "description": "Assume admin role"},
                    {"type": "exfiltration", "source": iam_roles[0] if iam_roles else iam_users[0],
                     "target": s3_nodes[0] if s3_nodes else "target",
                     "success_probability": 0.85, "data_amount": 1.0,
                     "description": "Exfiltrate all data"},
                ],
                expected_defenses=["MFA Required", "Zero Trust Deny", "Auto Key Rotation"],
                success_criteria="all_steps_blocked"
            ))
        
        # Scenario 3: Ransomware simulation
        if s3_nodes:
            scenarios.append(SimulationScenario(
                scenario_id="S003",
                name="Cloud Ransomware Attack",
                description="Attacker encrypts/deletes S3 data simulating ransomware",
                attack_sequence=[
                    {"type": "attack", "source": "external", "target": s3_nodes[0],
                     "success_probability": 0.50, "description": "Gain S3 write access"},
                    {"type": "attack", "source": s3_nodes[0], "target": s3_nodes[0],
                     "success_probability": 0.80, "description": "Delete all versioned objects"},
                ],
                expected_defenses=["S3 Versioning", "MFA Delete required", "CloudTrail"],
                success_criteria="all_steps_blocked"
            ))
        
        # Scenario 4: AZTCSE defense effectiveness test
        if public_nodes:
            scenarios.append(SimulationScenario(
                scenario_id="S004",
                name="AZTCSE Defense Validation",
                description="Test if AZTCSE autonomous response blocks a multi-stage attack",
                attack_sequence=[
                    {"type": "attack", "source": "external", "target": public_nodes[0],
                     "success_probability": 0.70, "description": "Probe public instance"},
                    {"type": "lateral_movement", "source": public_nodes[0],
                     "target": node_ids[1] if len(node_ids) > 1 else public_nodes[0],
                     "success_probability": 0.60, "description": "Lateral movement to internal"},
                    {"type": "privilege_escalation",
                     "source": node_ids[1] if len(node_ids) > 1 else public_nodes[0],
                     "target": iam_roles[0] if iam_roles else public_nodes[0],
                     "success_probability": 0.50, "description": "Privilege escalation"},
                ],
                expected_defenses=["AZTCSE Response", "Instance Isolation", "Zero Trust Deny"],
                success_criteria="any_step_blocked"
            ))
        
        return scenarios

    async def run_all_scenarios(self) -> List[SimulationResult]:
        """Run all predefined scenarios and return results."""
        scenarios = self.get_predefined_scenarios()
        results = []
        
        console.print(f"\n[bold magenta]🎮 Running {len(scenarios)} simulation scenarios...[/bold magenta]")
        
        for scenario in scenarios:
            result = await self.run_scenario(scenario)
            results.append(result)
            await asyncio.sleep(0.1)  # Small delay between scenarios
        
        return results

    async def validate_defense_change(self, change_description: str, 
                                       apply_fn) -> Dict[str, Any]:
        """
        Validate a proposed defense change by:
        1. Running scenarios BEFORE the change
        2. Applying the change to the twin
        3. Running scenarios AFTER
        4. Comparing outcomes
        """
        console.print(f"\n[cyan]🔬 Validating defense change: {change_description}[/cyan]")
        
        # Before state
        before_results = await self.run_all_scenarios()
        before_success_rate = sum(1 for r in before_results if r.attack_succeeded) / max(len(before_results), 1)
        
        # Apply change to twin (NOT to real cloud)
        console.print("[yellow]Applying change to Digital Twin...[/yellow]")
        await apply_fn(self.twin_nodes, self.twin_graph)
        
        # After state
        after_results = await self.run_all_scenarios()
        after_success_rate = sum(1 for r in after_results if r.attack_succeeded) / max(len(after_results), 1)
        
        improvement = before_success_rate - after_success_rate
        
        return {
            "change": change_description,
            "before_attack_success_rate": f"{before_success_rate:.1%}",
            "after_attack_success_rate": f"{after_success_rate:.1%}",
            "improvement": f"{improvement:.1%}",
            "recommendation": (
                f"DEPLOY: Change reduces attack success by {improvement:.1%}"
                if improvement > 0.1 else
                f"REVIEW: Change shows minimal improvement ({improvement:.1%})"
            ),
            "safe_to_deploy": improvement > 0,
        }

    def get_twin_report(self) -> Dict[str, Any]:
        """Return comprehensive twin simulation report."""
        if not self.simulation_history:
            return {"message": "No simulations run yet"}
        
        total = len(self.simulation_history)
        succeeded = sum(1 for r in self.simulation_history if r.attack_succeeded)
        
        return {
            "total_scenarios_run": total,
            "attack_success_rate": f"{succeeded/total:.1%}",
            "total_events_simulated": len(self.event_log),
            "avg_nodes_compromised": sum(len(r.nodes_compromised) for r in self.simulation_history) / total,
            "scenarios": [r.to_dict() for r in self.simulation_history],
            "overall_security_rating": "POOR" if succeeded/total > 0.7 else 
                                       "NEEDS_IMPROVEMENT" if succeeded/total > 0.4 else
                                       "ADEQUATE" if succeeded/total > 0.2 else "STRONG",
        }
