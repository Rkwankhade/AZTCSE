from __future__ import annotations

import networkx as nx

from app.core.attack_surface_graph import CloudAttackSurfaceGraph
from app.core.models import AttackPath, CloudInventory


class AttackSimulator:
    """Simulates attack paths before attackers find them."""

    def __init__(self) -> None:
        self.casg = CloudAttackSurfaceGraph()

    def simulate(self, inventory: CloudInventory, max_depth: int = 5) -> list[AttackPath]:
        graph = self.casg.build(inventory)
        entry_points = self.casg.entry_points(inventory)
        targets = self.casg.high_value_targets(inventory)
        paths: list[AttackPath] = []

        for entry in entry_points:
            for target in targets:
                if entry.id == target.id:
                    continue
                if not nx.has_path(graph, entry.id, target.id):
                    continue

                for route in nx.all_simple_paths(
                    graph,
                    entry.id,
                    target.id,
                    cutoff=max_depth,
                ):
                    paths.append(self._score_path(graph, route))

        paths.sort(key=lambda item: item.score, reverse=True)
        return paths[:15]

    def _score_path(self, graph: nx.DiGraph, route: list[str]) -> AttackPath:
        techniques = ["public entry point"]
        score = 30.0
        confidence = 0.55

        for node_id in route:
            node = graph.nodes[node_id]
            privileges = {item.lower() for item in node.get("privileges", [])}

            if node.get("exposure") == "public":
                score += 10
            if node.get("sensitive"):
                score += 20
                techniques.append("sensitive data access")
            if "admin" in privileges or "*" in privileges:
                score += 20
                confidence += 0.15
                techniques.append("privilege escalation candidate")
            if node.get("tags", {}).get("no_mfa"):
                score += 8
                techniques.append("weak identity control")

        for source, target in zip(route, route[1:]):
            edge = graph.edges[source, target]
            permissions = {item.lower() for item in edge.get("permissions", [])}
            if "*" in permissions or "admin" in permissions:
                score += 12
                techniques.append("high-permission trust traversal")
            else:
                score += 5
                techniques.append("trust relationship traversal")

        impact = "Potential path from public exposure to high-value cloud asset"
        return AttackPath(
            start=route[0],
            target=route[-1],
            route=route,
            techniques=sorted(set(techniques)),
            impact=impact,
            confidence=min(confidence, 0.95),
            score=min(score, 100.0),
        )
