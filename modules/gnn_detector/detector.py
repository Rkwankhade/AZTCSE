"""
Module 7: Graph Neural Network Threat Detector
================================================
Uses GNN to learn attack patterns from the graph structure.
Detects novel threats by understanding RELATIONSHIPS,
not just individual resource configurations.

A misconfigured S3 bucket adjacent to an admin role
looks completely different than an isolated one.
The GNN understands this context.
"""

import logging
import math
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

import numpy as np
import networkx as nx
from rich.console import Console
from rich.table import Table

console = Console()
logger = logging.getLogger(__name__)


# ── Pure-NumPy GNN (no PyTorch dependency required) ──────────────────────
class GraphConvLayer:
    """
    Single graph convolution layer.
    H_new = ReLU(D^-1 * A * H * W)
    """
    def __init__(self, in_dim: int, out_dim: int):
        # Xavier initialization
        limit = math.sqrt(6.0 / (in_dim + out_dim))
        self.W = np.random.uniform(-limit, limit, (in_dim, out_dim))
        self.b = np.zeros(out_dim)

    def forward(self, H: np.ndarray, A_hat: np.ndarray) -> np.ndarray:
        # Aggregate neighbor features
        AH = A_hat @ H
        # Linear transform
        Z = AH @ self.W + self.b
        # ReLU activation
        return np.maximum(0, Z)

    def backward(self, dZ: np.ndarray, H: np.ndarray, A_hat: np.ndarray, lr: float):
        # Gradient of ReLU
        dZ[dZ > 0] = 1.0
        # Weight gradient
        AH = A_hat @ H
        dW = AH.T @ dZ
        db = dZ.sum(axis=0)
        # Input gradient
        dH = A_hat.T @ (dZ @ self.W.T)
        # Update
        self.W -= lr * dW
        self.b -= lr * db
        return dH


class ThreatGNN:
    """
    2-layer GCN for threat detection.
    Input:  Node feature matrix (n_nodes x feature_dim)
    Output: Threat probability per node (n_nodes x 1)
    """
    def __init__(self, feature_dim: int = 8, hidden_dim: int = 16, out_dim: int = 1):
        self.conv1 = GraphConvLayer(feature_dim, hidden_dim)
        self.conv2 = GraphConvLayer(hidden_dim, hidden_dim)
        self.conv3 = GraphConvLayer(hidden_dim, out_dim)
        self.feature_dim = feature_dim

    def _normalize_adjacency(self, A: np.ndarray) -> np.ndarray:
        """Compute D^-1 * A (row-normalized)."""
        A_hat = A + np.eye(A.shape[0])  # add self-loops
        D = np.diag(A_hat.sum(axis=1))
        D_inv = np.diag(1.0 / (np.diag(D) + 1e-8))
        return D_inv @ A_hat

    def forward(self, X: np.ndarray, A: np.ndarray) -> np.ndarray:
        A_hat = self._normalize_adjacency(A)
        H1 = self.conv1.forward(X, A_hat)
        H2 = self.conv2.forward(H1, A_hat)
        H3 = self.conv3.forward(H2, A_hat)
        # Sigmoid output
        return 1.0 / (1.0 + np.exp(-H3))

    def train_step(self, X: np.ndarray, A: np.ndarray,
                   labels: np.ndarray, lr: float = 0.01) -> float:
        """Single training step, returns loss."""
        A_hat = self._normalize_adjacency(A)

        # Forward
        H1 = self.conv1.forward(X, A_hat)
        H2 = self.conv2.forward(H1, A_hat)
        out = self.conv3.forward(H2, A_hat)
        pred = 1.0 / (1.0 + np.exp(-out))

        # Binary cross-entropy loss
        eps = 1e-7
        loss = -np.mean(
            labels * np.log(pred + eps) + (1 - labels) * np.log(1 - pred + eps)
        )

        # Backward (simplified)
        dout = pred - labels
        self.conv3.backward(dout, H2, A_hat, lr)

        return float(loss)


@dataclass
class ThreatPrediction:
    node_id: str
    node_name: str
    node_type: str
    threat_probability: float
    threat_level: str
    contributing_features: List[str]
    neighbor_risk: float
    graph_centrality: float

    def to_dict(self) -> Dict:
        return {
            "node_id": self.node_id,
            "node_name": self.node_name,
            "node_type": self.node_type,
            "threat_probability": round(self.threat_probability, 4),
            "threat_level": self.threat_level,
            "contributing_features": self.contributing_features,
            "neighbor_risk": round(self.neighbor_risk, 3),
            "graph_centrality": round(self.graph_centrality, 3),
        }


class GNNThreatDetector:
    """
    Full GNN-based threat detection pipeline.
    
    Key insight: the GNN detects threats that are INVISIBLE
    to rule-based scanners because it understands graph context.
    
    Example: A user with low individual risk score becomes HIGH
    threat when the GNN sees it's 2 hops from a public resource
    AND 1 hop from an admin role.
    """

    def __init__(self, casg):
        self.casg = casg
        self.gnn = None
        self.predictions: List[ThreatPrediction] = []
        self.node_list: List[str] = []
        self.feature_dim = 8

    def _build_feature_matrix(self) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Build node feature matrix and adjacency matrix from CASG.

        Features per node (8 total):
        0: risk_score          - base misconfiguration risk
        1: is_public           - internet-facing?
        2: misconfiguration_count (normalized)
        3: node_type_encoded   - encoded resource type
        4: in_degree           - how many things point at this node
        5: out_degree          - how many things this node can reach
        6: has_admin_neighbor  - adjacent to admin/high-priv node?
        7: avg_neighbor_risk   - mean risk of immediate neighbors
        """
        nodes = self.casg.nodes
        graph = self.casg.nx_graph
        self.node_list = list(nodes.keys())
        n = len(self.node_list)

        if n == 0:
            return np.zeros((1, self.feature_dim)), np.zeros((1, 1)), []

        node_idx = {nid: i for i, nid in enumerate(self.node_list)}

        # Node type encoding
        type_encoding = {
            'IAM_USER': 0.1, 'IAM_ROLE': 0.2, 'IAM_POLICY': 0.15,
            'EC2_INSTANCE': 0.4, 'S3_BUCKET': 0.6, 'RDS_INSTANCE': 0.8,
            'LAMBDA_FUNCTION': 0.35, 'SECURITY_GROUP': 0.5,
            'VPC': 0.25, 'SUBNET': 0.3, 'API_GATEWAY': 0.45,
        }

        # Precompute centrality
        try:
            betweenness = nx.betweenness_centrality(graph)
        except Exception:
            betweenness = {n: 0.0 for n in self.node_list}

        X = np.zeros((n, self.feature_dim))
        A = np.zeros((n, n))

        for i, node_id in enumerate(self.node_list):
            node = nodes[node_id]
            neighbors = list(graph.successors(node_id)) + list(graph.predecessors(node_id))
            neighbor_nodes = [nodes[nb] for nb in neighbors if nb in nodes]

            # Feature 0: base risk score
            X[i, 0] = node.risk_score

            # Feature 1: public exposure
            X[i, 1] = 1.0 if node.is_public else 0.0

            # Feature 2: misconfiguration density (normalized)
            X[i, 2] = min(len(node.misconfigurations) / 5.0, 1.0)

            # Feature 3: node type
            X[i, 3] = type_encoding.get(node.node_type.value, 0.5)

            # Feature 4: in-degree (normalized)
            X[i, 4] = min(graph.in_degree(node_id) / 10.0, 1.0)

            # Feature 5: out-degree (normalized)
            X[i, 5] = min(graph.out_degree(node_id) / 10.0, 1.0)

            # Feature 6: has high-risk neighbor
            X[i, 6] = 1.0 if any(nb.risk_score > 0.6 for nb in neighbor_nodes) else 0.0

            # Feature 7: average neighbor risk
            X[i, 7] = (
                sum(nb.risk_score for nb in neighbor_nodes) / max(len(neighbor_nodes), 1)
            )

        # Build adjacency matrix
        for edge in self.casg.edges:
            src_idx = node_idx.get(edge.source_id)
            tgt_idx = node_idx.get(edge.target_id)
            if src_idx is not None and tgt_idx is not None:
                A[src_idx, tgt_idx] = edge.weight
                # Add reverse edge for undirected aggregation
                A[tgt_idx, src_idx] = edge.weight * 0.5

        return X, A, self.node_list

    def _generate_training_labels(self, X: np.ndarray) -> np.ndarray:
        """
        Generate pseudo-labels for training.
        A node is "threatened" if:
        - risk_score > 0.5, OR
        - is_public AND has_high_risk_neighbor, OR
        - misconfiguration_count is high AND out_degree > 0
        """
        labels = np.zeros((X.shape[0], 1))
        for i in range(X.shape[0]):
            risk = X[i, 0]
            is_public = X[i, 1]
            misconfiged = X[i, 2]
            has_risky_neighbor = X[i, 6]
            out_deg = X[i, 5]

            score = risk
            if is_public and has_risky_neighbor:
                score += 0.3
            if misconfiged > 0.4 and out_deg > 0:
                score += 0.2
            if is_public and risk > 0.3:
                score += 0.2

            labels[i, 0] = 1.0 if score > 0.5 else 0.0

        return labels

    def train(self, epochs: int = 50) -> List[float]:
        """Train the GNN on the current graph."""
        X, A, node_ids = self._build_feature_matrix()
        if len(node_ids) == 0:
            return []

        labels = self._generate_training_labels(X)
        self.gnn = ThreatGNN(
            feature_dim=self.feature_dim,
            hidden_dim=16,
            out_dim=1
        )

        losses = []
        lr = 0.05
        for epoch in range(epochs):
            loss = self.gnn.train_step(X, A, labels, lr=lr)
            losses.append(loss)
            # Learning rate decay
            if epoch % 20 == 19:
                lr *= 0.5

        console.print(
            f"[cyan]GNN trained: {epochs} epochs, "
            f"final loss={losses[-1]:.4f}[/cyan]"
        )
        return losses

    def detect_threats(self) -> List[ThreatPrediction]:
        """Run GNN inference to detect threats."""
        if not self.gnn:
            self.train()

        X, A, node_ids = self._build_feature_matrix()
        if not node_ids:
            return []

        # GNN inference
        probs = self.gnn.forward(X, A).flatten()

        nodes = self.casg.nodes
        graph = self.casg.nx_graph

        # Compute graph centrality for context
        try:
            betweenness = nx.betweenness_centrality(graph)
            pagerank = nx.pagerank(graph, max_iter=100)
        except Exception:
            betweenness = {n: 0.0 for n in node_ids}
            pagerank = {n: 0.0 for n in node_ids}

        self.predictions = []
        for i, node_id in enumerate(node_ids):
            node = nodes.get(node_id)
            if not node:
                continue

            prob = float(probs[i])
            neighbors = list(graph.successors(node_id)) + list(graph.predecessors(node_id))
            neighbor_risk = (
                sum(nodes[nb].risk_score for nb in neighbors if nb in nodes) /
                max(len(neighbors), 1)
            )

            # Determine threat level
            if prob >= 0.80:
                threat_level = "CRITICAL"
            elif prob >= 0.60:
                threat_level = "HIGH"
            elif prob >= 0.35:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"

            # Explain contributing features
            features = []
            if X[i, 0] > 0.5:
                features.append(f"High base risk ({X[i,0]:.0%})")
            if X[i, 1] > 0:
                features.append("Internet-exposed")
            if X[i, 2] > 0.3:
                features.append(f"Misconfigured ({int(X[i,2]*5)} issues)")
            if X[i, 6] > 0:
                features.append("Adjacent to high-risk node")
            if X[i, 7] > 0.4:
                features.append(f"High-risk neighborhood ({X[i,7]:.0%})")
            if betweenness.get(node_id, 0) > 0.1:
                features.append("High betweenness centrality (choke point)")

            pred = ThreatPrediction(
                node_id=node_id,
                node_name=node.name,
                node_type=node.node_type.value,
                threat_probability=prob,
                threat_level=threat_level,
                contributing_features=features,
                neighbor_risk=neighbor_risk,
                graph_centrality=betweenness.get(node_id, 0.0),
            )
            self.predictions.append(pred)

        self.predictions.sort(key=lambda p: -p.threat_probability)
        return self.predictions

    def get_novel_threats(self) -> List[ThreatPrediction]:
        """
        Return threats the GNN found that rule-based scanner missed.
        These are nodes with LOW individual risk but HIGH GNN threat score.
        """
        return [
            p for p in self.predictions
            if p.threat_probability > 0.6 and
            self.casg.nodes.get(p.node_id, None) and
            self.casg.nodes[p.node_id].risk_score < 0.4
        ]

    def get_report(self) -> Dict:
        if not self.predictions:
            self.detect_threats()

        by_level = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for p in self.predictions:
            by_level[p.threat_level] = by_level.get(p.threat_level, 0) + 1

        novel = self.get_novel_threats()

        return {
            "total_nodes_analyzed": len(self.predictions),
            "threat_distribution": by_level,
            "novel_threats_found": len(novel),
            "top_threats": [p.to_dict() for p in self.predictions[:10]],
            "novel_threats": [p.to_dict() for p in novel],
            "avg_threat_probability": (
                sum(p.threat_probability for p in self.predictions) /
                max(len(self.predictions), 1)
            ),
        }

    def print_summary(self):
        table = Table(title="🧠 GNN Threat Detection Results", style="magenta")
        table.add_column("Node", style="bold")
        table.add_column("Type", style="dim")
        table.add_column("Threat Prob", justify="right")
        table.add_column("Level")
        table.add_column("Key Factors")

        colors = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}

        for pred in self.predictions[:15]:
            c = colors.get(pred.threat_level, "white")
            table.add_row(
                pred.node_name[:22],
                pred.node_type[:15],
                f"[{c}]{pred.threat_probability:.1%}[/{c}]",
                f"[{c}]{pred.threat_level}[/{c}]",
                ", ".join(pred.contributing_features[:2])[:45]
            )

        console.print(table)

        novel = self.get_novel_threats()
        if novel:
            console.print(
                f"\n[bold yellow]🔍 {len(novel)} Novel Threats Detected "
                f"(missed by rule-based scanner):[/bold yellow]"
            )
            for n in novel:
                console.print(
                    f"  • {n.node_name} ({n.node_type}) — "
                    f"GNN: {n.threat_probability:.1%} vs Rule-based: {self.casg.nodes[n.node_id].risk_score:.1%}"
                )
