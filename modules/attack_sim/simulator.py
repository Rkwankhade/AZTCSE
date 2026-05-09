"""
Module 2: AI-Powered Attack Simulator
======================================
Reinforcement Learning agent that simulates attacker behavior.
Finds attack paths BEFORE real attackers do.
Inspired by red teaming + pentesting methodology.

Attack types simulated:
- Privilege Escalation
- Lateral Movement  
- Data Exfiltration
- Credential Theft
- Persistence
"""

import random
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from copy import deepcopy

import numpy as np
import networkx as nx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()
logger = logging.getLogger(__name__)


class AttackTechnique(str, Enum):
    """MITRE ATT&CK inspired techniques for cloud."""
    # Initial Access
    PHISHING = "T1566"
    VALID_ACCOUNTS = "T1078"
    EXPOSED_KEYS = "T1552.001"
    # Privilege Escalation
    ROLE_ASSUMPTION = "T1548.005"
    POLICY_MANIPULATION = "T1484.001"
    INSTANCE_METADATA = "T1552.005"
    # Lateral Movement
    INTERNAL_SPEARPHISH = "T1534"
    CLOUD_SERVICE_DISCOVERY = "T1580"
    # Exfiltration
    S3_EXFIL = "T1530"
    API_EXFIL = "T1567"
    # Persistence
    CREATE_ACCOUNT = "T1136"
    CREATE_ACCESS_KEY = "T1098.001"


@dataclass
class AttackAction:
    technique: AttackTechnique
    source_node: str
    target_node: str
    success_probability: float
    damage_score: float  # 0-1 how damaging if successful
    stealth_score: float  # 0-1 how stealthy (harder to detect)
    description: str

    def to_dict(self):
        return {
            "technique": self.technique.value,
            "source_node": self.source_node,
            "target_node": self.target_node,
            "success_probability": round(self.success_probability, 3),
            "damage_score": round(self.damage_score, 3),
            "stealth_score": round(self.stealth_score, 3),
            "description": self.description,
        }


@dataclass
class AttackPath:
    """A complete attack chain from initial access to objective."""
    path_id: str
    steps: List[AttackAction] = field(default_factory=list)
    overall_success_prob: float = 0.0
    total_damage_score: float = 0.0
    avg_stealth: float = 0.0
    objective: str = "data_exfiltration"
    criticality: str = "LOW"  # LOW / MEDIUM / HIGH / CRITICAL

    def calculate_metrics(self):
        if not self.steps:
            return
        # Probability = product of each step's probability
        self.overall_success_prob = 1.0
        for step in self.steps:
            self.overall_success_prob *= step.success_probability
        
        self.total_damage_score = sum(s.damage_score for s in self.steps)
        self.avg_stealth = sum(s.stealth_score for s in self.steps) / len(self.steps)
        
        # Determine criticality
        combined = self.overall_success_prob * self.total_damage_score
        if combined > 0.5:
            self.criticality = "CRITICAL"
        elif combined > 0.3:
            self.criticality = "HIGH"
        elif combined > 0.15:
            self.criticality = "MEDIUM"
        else:
            self.criticality = "LOW"

    def to_dict(self):
        return {
            "path_id": self.path_id,
            "steps": [s.to_dict() for s in self.steps],
            "overall_success_probability": round(self.overall_success_prob, 4),
            "total_damage_score": round(self.total_damage_score, 3),
            "avg_stealth": round(self.avg_stealth, 3),
            "objective": self.objective,
            "criticality": self.criticality,
            "step_count": len(self.steps),
        }


class CloudEnvironment:
    """
    RL Environment representing the cloud infrastructure.
    The RL agent (attacker) navigates this environment
    to find optimal attack paths.
    """

    def __init__(self, graph, nodes: dict, edges: list):
        self.original_graph = graph
        self.graph = deepcopy(graph)
        self.nodes = nodes
        self.edges = edges
        
        self.current_position: Optional[str] = None
        self.compromised_nodes: set = set()
        self.collected_data: float = 0.0
        self.steps_taken: int = 0
        self.max_steps: int = 20
        self.detection_level: float = 0.0
        
        # State space size
        self.n_nodes = len(nodes)
        self.state_dim = self.n_nodes * 4  # per-node: compromised, risk, public, type_encoded
        
        # Action space = possible moves between nodes
        self._node_list = list(nodes.keys())
        self._node_idx = {n: i for i, n in enumerate(self._node_list)}

    def reset(self) -> np.ndarray:
        """Reset environment to initial state."""
        self.graph = deepcopy(self.original_graph)
        self.compromised_nodes = set()
        self.collected_data = 0.0
        self.steps_taken = 0
        self.detection_level = 0.0
        
        # Start from an external entry point or low-privilege user
        entry_points = [
            nid for nid, node in self.nodes.items()
            if node.is_public or node.node_type.value in ['IAM_USER', 'EC2_INSTANCE']
        ]
        
        if entry_points:
            self.current_position = random.choice(entry_points)
        else:
            self.current_position = random.choice(self._node_list)
        
        self.compromised_nodes.add(self.current_position)
        return self._get_state()

    def _get_state(self) -> np.ndarray:
        """Encode graph state as feature vector for RL agent."""
        state = np.zeros(self.state_dim)
        
        for i, node_id in enumerate(self._node_list):
            base = i * 4
            node = self.nodes.get(node_id)
            if node:
                state[base] = 1.0 if node_id in self.compromised_nodes else 0.0
                state[base + 1] = node.risk_score
                state[base + 2] = 1.0 if node.is_public else 0.0
                # Encode node type as numeric value
                type_map = {
                    'IAM_USER': 0.1, 'IAM_ROLE': 0.2, 'EC2_INSTANCE': 0.4,
                    'S3_BUCKET': 0.6, 'RDS_INSTANCE': 0.8, 'LAMBDA_FUNCTION': 0.3,
                }
                state[base + 3] = type_map.get(node.node_type.value, 0.5)
        
        return state

    def get_valid_actions(self) -> List[str]:
        """Return nodes reachable from current position."""
        if not self.current_position:
            return []
        
        neighbors = list(self.graph.successors(self.current_position))
        uncompromised_reachable = [
            n for n in neighbors
            if n not in self.compromised_nodes
        ]
        # Can also target already-compromised nodes for lateral movement
        return neighbors if not uncompromised_reachable else uncompromised_reachable

    def step(self, target_node_id: str) -> Tuple[np.ndarray, float, bool, dict]:
        """
        Take an attack action.
        Returns: (next_state, reward, done, info)
        """
        self.steps_taken += 1
        
        if target_node_id not in self.graph.successors(self.current_position):
            # Invalid move - node not reachable
            return self._get_state(), -1.0, False, {"info": "invalid_action"}
        
        target_node = self.nodes.get(target_node_id)
        if not target_node:
            return self._get_state(), -0.5, False, {"info": "unknown_node"}
        
        # Calculate success probability based on node's defenses
        base_success_prob = 1.0 - target_node.risk_score * 0.3
        
        # Misconfigured nodes are easier to exploit
        if target_node.misconfigurations:
            base_success_prob += 0.2 * min(len(target_node.misconfigurations) / 5, 1.0)
        
        # Public nodes are easier to reach
        if target_node.is_public:
            base_success_prob += 0.1
        
        base_success_prob = min(base_success_prob, 0.95)
        
        # Determine if attack succeeds
        success = random.random() < base_success_prob
        
        reward = 0.0
        info = {}
        
        if success:
            self.compromised_nodes.add(target_node_id)
            self.current_position = target_node_id
            
            # Reward based on node value
            node_value = target_node.risk_score + (0.5 if target_node.is_public else 0)
            
            # Extra reward for high-value targets
            if target_node.node_type.value == 'S3_BUCKET':
                self.collected_data += 0.3
                reward = 2.0 + node_value
            elif target_node.node_type.value in ['RDS_INSTANCE']:
                self.collected_data += 0.5
                reward = 3.0 + node_value
            elif target_node.node_type.value == 'IAM_ROLE':
                reward = 1.5 + node_value  # Privilege escalation
            else:
                reward = 0.5 + node_value
            
            info['success'] = True
            info['node_type'] = target_node.node_type.value
        else:
            # Unsuccessful attack - triggers alerts
            self.detection_level += 0.15
            reward = -0.5
            info['success'] = False
            info['detected'] = self.detection_level > 0.7
        
        # Detection penalty
        reward -= self.detection_level * 0.3
        
        # Time pressure
        reward -= 0.02 * self.steps_taken
        
        # Check termination conditions
        done = (
            self.steps_taken >= self.max_steps or
            self.detection_level >= 1.0 or
            self.collected_data >= 1.0  # Objective achieved
        )
        
        info['detection_level'] = self.detection_level
        info['data_collected'] = self.collected_data
        info['compromised_count'] = len(self.compromised_nodes)
        
        return self._get_state(), reward, done, info


class QLearningAttacker:
    """
    Q-Learning based attacker agent.
    Learns optimal attack strategies through experience.
    Uses epsilon-greedy exploration.
    """

    def __init__(self, state_dim: int, n_actions: int,
                 learning_rate: float = 0.1,
                 discount_factor: float = 0.95,
                 epsilon: float = 1.0,
                 epsilon_min: float = 0.05,
                 epsilon_decay: float = 0.995):
        
        self.state_dim = state_dim
        self.n_actions = n_actions
        self.lr = learning_rate
        self.gamma = discount_factor
        self.epsilon = epsilon
        self.epsilon_min = epsilon_min
        self.epsilon_decay = epsilon_decay
        
        # Q-table with feature hashing for continuous state space
        self.q_table: Dict[str, Dict[int, float]] = {}
        self.best_episodes: List[Dict] = []

    def _state_to_key(self, state: np.ndarray) -> str:
        """Hash continuous state to discrete key."""
        # Discretize state vector
        discretized = (state * 10).astype(int)
        return ",".join(map(str, discretized[:20]))  # Use first 20 features

    def choose_action(self, state: np.ndarray, valid_action_indices: List[int]) -> int:
        """Epsilon-greedy action selection."""
        if not valid_action_indices:
            return 0
        
        if random.random() < self.epsilon:
            return random.choice(valid_action_indices)
        
        state_key = self._state_to_key(state)
        if state_key not in self.q_table:
            return random.choice(valid_action_indices)
        
        q_values = self.q_table[state_key]
        best_action = max(valid_action_indices, 
                         key=lambda a: q_values.get(a, 0.0))
        return best_action

    def update(self, state: np.ndarray, action: int, reward: float,
               next_state: np.ndarray, done: bool, valid_next_actions: List[int]):
        """Q-value update."""
        state_key = self._state_to_key(state)
        next_key = self._state_to_key(next_state)
        
        if state_key not in self.q_table:
            self.q_table[state_key] = {}
        if next_key not in self.q_table:
            self.q_table[next_key] = {}
        
        current_q = self.q_table[state_key].get(action, 0.0)
        
        if done or not valid_next_actions:
            target = reward
        else:
            next_max_q = max(
                self.q_table[next_key].get(a, 0.0) 
                for a in valid_next_actions
            )
            target = reward + self.gamma * next_max_q
        
        # Q-learning update
        self.q_table[state_key][action] = current_q + self.lr * (target - current_q)
        
        # Decay exploration
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay


class AIAttackSimulator:
    """
    Main AI-powered attack simulation engine.
    Uses RL to discover attack paths + graph traversal
    for comprehensive attack surface analysis.
    """

    def __init__(self, casg):
        self.casg = casg
        self.attack_paths: List[AttackPath] = []
        self.training_history: List[Dict] = []

    async def run_full_simulation(self, n_episodes: int = 500) -> List[AttackPath]:
        """
        Run the full attack simulation.
        Combines RL training + graph-based path analysis.
        """
        console.print("[bold red]🔴 Launching AI Attack Simulation...[/bold red]")
        
        # Phase 1: Graph-based attack path discovery
        graph_paths = await self._graph_based_attack_discovery()
        
        # Phase 2: RL-based simulation
        rl_paths = await self._rl_simulation(n_episodes)
        
        # Phase 3: Combine and rank paths
        all_paths = graph_paths + rl_paths
        all_paths.sort(key=lambda p: (
            -{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(p.criticality, 0)
        ))
        
        self.attack_paths = all_paths[:20]  # Keep top 20
        
        console.print(f"[red]⚠️  Found {len(self.attack_paths)} attack paths![/red]")
        for path in self.attack_paths[:5]:
            console.print(f"  [{path.criticality}] {path.objective}: "
                         f"{len(path.steps)} steps, "
                         f"success={path.overall_success_prob:.1%}")
        
        return self.attack_paths

    async def _graph_based_attack_discovery(self) -> List[AttackPath]:
        """
        Graph traversal-based attack path discovery.
        Simulates specific MITRE ATT&CK technique chains.
        """
        paths = []
        nodes = self.casg.nodes
        graph = self.casg.nx_graph
        path_counter = 0
        
        # --- Attack Scenario 1: Privilege Escalation ---
        for src_id, src_node in nodes.items():
            if src_node.node_type.value not in ['IAM_USER', 'EC2_INSTANCE']:
                continue
            
            for role_id, role_node in nodes.items():
                if role_node.node_type.value != 'IAM_ROLE':
                    continue
                
                if not nx.has_path(graph, src_id, role_id):
                    continue
                
                for nx_path in nx.all_simple_paths(graph, src_id, role_id, cutoff=3):
                    path_counter += 1
                    attack_path = AttackPath(
                        path_id=f"PRIVESC-{path_counter:04d}",
                        objective="privilege_escalation"
                    )
                    
                    for i in range(len(nx_path) - 1):
                        src = nx_path[i]
                        tgt = nx_path[i + 1]
                        src_n = nodes.get(src)
                        tgt_n = nodes.get(tgt)
                        
                        if not src_n or not tgt_n:
                            continue
                        
                        technique = AttackTechnique.ROLE_ASSUMPTION
                        success_prob = 0.7 + (0.15 if tgt_n.misconfigurations else 0)
                        damage = tgt_n.risk_score
                        stealth = 0.6 if not tgt_n.misconfigurations else 0.3
                        
                        action = AttackAction(
                            technique=technique,
                            source_node=src,
                            target_node=tgt,
                            success_probability=min(success_prob, 0.95),
                            damage_score=damage,
                            stealth_score=stealth,
                            description=f"Assume role {tgt_n.name} from {src_n.name}"
                        )
                        attack_path.steps.append(action)
                    
                    if attack_path.steps:
                        attack_path.calculate_metrics()
                        paths.append(attack_path)
                        if path_counter > 20:
                            break
            if path_counter > 20:
                break
        
        # --- Attack Scenario 2: Data Exfiltration via Public S3 ---
        public_buckets = [
            nid for nid, n in nodes.items() 
            if n.node_type.value == 'S3_BUCKET' and n.is_public
        ]
        
        for bucket_id in public_buckets:
            path_counter += 1
            attack_path = AttackPath(
                path_id=f"EXFIL-{path_counter:04d}",
                objective="data_exfiltration"
            )
            bucket_node = nodes[bucket_id]
            
            action = AttackAction(
                technique=AttackTechnique.S3_EXFIL,
                source_node="external_attacker",
                target_node=bucket_id,
                success_probability=0.95,
                damage_score=0.9,
                stealth_score=0.2,
                description=f"Directly exfiltrate data from public S3 bucket: {bucket_node.name}"
            )
            attack_path.steps.append(action)
            attack_path.calculate_metrics()
            paths.append(attack_path)
        
        # --- Attack Scenario 3: Exposed Credentials → Lateral Movement ---
        high_risk_users = [
            (nid, n) for nid, n in nodes.items()
            if n.node_type.value == 'IAM_USER' and n.risk_score > 0.5
        ]
        
        for user_id, user_node in high_risk_users:
            path_counter += 1
            attack_path = AttackPath(
                path_id=f"LATERAL-{path_counter:04d}",
                objective="lateral_movement_to_data"
            )
            
            # Step 1: Compromise user
            action1 = AttackAction(
                technique=AttackTechnique.EXPOSED_KEYS,
                source_node="external_attacker",
                target_node=user_id,
                success_probability=0.7 + (0.2 if "without MFA" in " ".join(user_node.misconfigurations) else 0),
                damage_score=0.4,
                stealth_score=0.5,
                description=f"Steal credentials / exposed access keys for {user_node.name}"
            )
            attack_path.steps.append(action1)
            
            # Step 2: Find reachable high-value targets
            reachable = list(self.casg.nx_graph.successors(user_id))
            for target_id in reachable[:2]:
                target_n = nodes.get(target_id)
                if target_n and target_n.node_type.value in ['S3_BUCKET', 'RDS_INSTANCE']:
                    action2 = AttackAction(
                        technique=AttackTechnique.CLOUD_SERVICE_DISCOVERY,
                        source_node=user_id,
                        target_node=target_id,
                        success_probability=0.8,
                        damage_score=target_n.risk_score,
                        stealth_score=0.6,
                        description=f"Access {target_n.name} using compromised credentials"
                    )
                    attack_path.steps.append(action2)
            
            attack_path.calculate_metrics()
            paths.append(attack_path)
        
        return paths

    async def _rl_simulation(self, n_episodes: int) -> List[AttackPath]:
        """Run RL agent training simulation."""
        if not self.casg.nodes:
            return []
        
        env = CloudEnvironment(
            self.casg.nx_graph,
            self.casg.nodes,
            self.casg.edges
        )
        
        agent = QLearningAttacker(
            state_dim=env.state_dim,
            n_actions=env.n_nodes,
            learning_rate=0.1,
            discount_factor=0.95
        )
        
        best_attack_paths = []
        node_list = list(self.casg.nodes.keys())
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[red]Training RL attacker...", total=n_episodes)
            
            for episode in range(n_episodes):
                state = env.reset()
                episode_reward = 0.0
                episode_actions = []
                done = False
                
                while not done:
                    valid_targets = env.get_valid_actions()
                    if not valid_targets:
                        break
                    
                    valid_indices = [
                        node_list.index(t) for t in valid_targets 
                        if t in node_list
                    ]
                    if not valid_indices:
                        break
                    
                    action_idx = agent.choose_action(state, valid_indices)
                    if action_idx >= len(node_list):
                        break
                    
                    target = node_list[action_idx]
                    next_state, reward, done, info = env.step(target)
                    
                    next_valid = env.get_valid_actions()
                    next_valid_indices = [
                        node_list.index(t) for t in next_valid 
                        if t in node_list
                    ]
                    
                    agent.update(state, action_idx, reward, next_state, done, next_valid_indices)
                    
                    if info.get('success'):
                        episode_actions.append({
                            'source': env.current_position,
                            'target': target,
                            'reward': reward
                        })
                    
                    state = next_state
                    episode_reward += reward
                
                self.training_history.append({
                    'episode': episode,
                    'reward': episode_reward,
                    'compromised': len(env.compromised_nodes),
                    'detection': env.detection_level,
                    'epsilon': agent.epsilon
                })
                
                # Save high-reward episodes as attack paths
                if episode_reward > 3.0 and episode_actions:
                    path = self._episode_to_attack_path(episode_actions, episode_reward)
                    if path:
                        best_attack_paths.append(path)
                
                progress.update(task, advance=1)
        
        # Return unique top paths
        return best_attack_paths[:10]

    def _episode_to_attack_path(self, actions: List[Dict], reward: float) -> Optional[AttackPath]:
        """Convert RL episode actions to AttackPath object."""
        if not actions:
            return None
        
        path = AttackPath(
            path_id=f"RL-{random.randint(1000, 9999)}",
            objective="rl_discovered_path"
        )
        
        for action in actions:
            target = action['target']
            target_node = self.casg.nodes.get(target)
            if not target_node:
                continue
            
            step = AttackAction(
                technique=AttackTechnique.VALID_ACCOUNTS,
                source_node=action['source'],
                target_node=target,
                success_probability=0.7 + (action['reward'] / 20),
                damage_score=target_node.risk_score,
                stealth_score=0.5,
                description=f"RL discovered: move to {target_node.name}"
            )
            path.steps.append(step)
        
        path.calculate_metrics()
        return path

    def get_critical_paths(self) -> List[AttackPath]:
        return [p for p in self.attack_paths if p.criticality == "CRITICAL"]

    def get_attack_statistics(self) -> Dict:
        if not self.attack_paths:
            return {}
        
        criticality_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for path in self.attack_paths:
            criticality_dist[path.criticality] = criticality_dist.get(path.criticality, 0) + 1
        
        return {
            "total_paths_found": len(self.attack_paths),
            "criticality_distribution": criticality_dist,
            "avg_success_probability": sum(p.overall_success_prob for p in self.attack_paths) / len(self.attack_paths),
            "avg_steps_per_path": sum(len(p.steps) for p in self.attack_paths) / len(self.attack_paths),
            "most_targeted_nodes": self._get_most_targeted(),
            "highest_risk_path": self.attack_paths[0].to_dict() if self.attack_paths else None,
        }

    def _get_most_targeted(self) -> List[Dict]:
        target_count: Dict[str, int] = {}
        for path in self.attack_paths:
            for step in path.steps:
                target_count[step.target_node] = target_count.get(step.target_node, 0) + 1
        
        sorted_targets = sorted(target_count.items(), key=lambda x: -x[1])
        return [{"node_id": k, "times_targeted": v} for k, v in sorted_targets[:5]]
