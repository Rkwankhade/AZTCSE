from __future__ import annotations

import os
from typing import Any

import networkx as nx
from neo4j import GraphDatabase

from app.core.models import CloudInventory, CloudResource


class CloudAttackSurfaceGraph:
    """Builds the Cloud Attack Surface Graph (CASG)."""

    def build(self, inventory: CloudInventory) -> nx.DiGraph:
        graph = nx.DiGraph()

        for resource in inventory.resources:
            graph.add_node(
                resource.id,
                name=resource.name,
                type=resource.type,
                provider=resource.provider,
                exposure=resource.exposure.value,
                privileges=resource.privileges,
                sensitive=resource.sensitive,
                tags=resource.tags,
            )

        for relationship in inventory.relationships:
            graph.add_edge(
                relationship.source,
                relationship.target,
                kind=relationship.kind,
                permissions=relationship.permissions,
                condition=relationship.condition,
            )

        return graph

    def entry_points(self, inventory: CloudInventory) -> list[CloudResource]:
        return [
            resource
            for resource in inventory.resources
            if resource.exposure.value == "public"
            or bool(resource.tags.get("internet_exposed"))
        ]

    def high_value_targets(self, inventory: CloudInventory) -> list[CloudResource]:
        target_types = {"database", "s3_bucket", "secret", "iam_role", "kms_key"}
        return [
            resource
            for resource in inventory.resources
            if resource.sensitive
            or resource.type in target_types
            or "admin" in {item.lower() for item in resource.privileges}
        ]

    def graph_payload(self, inventory: CloudInventory) -> dict[str, Any]:
        graph = self.build(inventory)
        return {
            "nodes": [
                {"id": node, **attrs}
                for node, attrs in graph.nodes(data=True)
            ],
            "edges": [
                {"source": source, "target": target, **attrs}
                for source, target, attrs in graph.edges(data=True)
            ],
        }

    def cypher_preview(self, inventory: CloudInventory) -> list[str]:
        statements: list[str] = []
        for resource in inventory.resources:
            statements.append(
                "MERGE (r:CloudResource {id: '%s'}) "
                "SET r.name = '%s', r.type = '%s', r.exposure = '%s'"
                % (
                    resource.id.replace("'", "\\'"),
                    resource.name.replace("'", "\\'"),
                    resource.type.replace("'", "\\'"),
                    resource.exposure.value.replace("'", "\\'"),
                )
            )

        for relation in inventory.relationships:
            rel_type = relation.kind.upper().replace("-", "_").replace(" ", "_")
            statements.append(
                "MATCH (a:CloudResource {id: '%s'}), (b:CloudResource {id: '%s'}) "
                "MERGE (a)-[:%s]->(b)"
                % (
                    relation.source.replace("'", "\\'"),
                    relation.target.replace("'", "\\'"),
                    rel_type,
                )
            )

        return statements

    def push_to_neo4j(self, inventory: CloudInventory) -> int:
        uri = os.getenv("NEO4J_URI", "bolt://127.0.0.1:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "aztcsepass")

        statements = self.cypher_preview(inventory)
        driver = GraphDatabase.driver(uri, auth=(user, password))
        try:
            with driver.session() as session:
                for statement in statements:
                    session.run(statement)
        finally:
            driver.close()

        return len(statements)
