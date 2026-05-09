"""
Module 1: Cloud Attack Surface Graph (CASG)
============================================
Builds a real-time graph model of cloud infrastructure.
Nodes = Resources | Edges = Trust Relationships
This becomes the "battle map" for the entire engine.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

import boto3
import networkx as nx
from neo4j import AsyncGraphDatabase, AsyncDriver
from rich.console import Console
from rich.table import Table

console = Console()
logger = logging.getLogger(__name__)


class NodeType(str, Enum):
    IAM_USER = "IAM_USER"
    IAM_ROLE = "IAM_ROLE"
    IAM_POLICY = "IAM_POLICY"
    IAM_GROUP = "IAM_GROUP"
    EC2_INSTANCE = "EC2_INSTANCE"
    S3_BUCKET = "S3_BUCKET"
    LAMBDA_FUNCTION = "LAMBDA_FUNCTION"
    RDS_INSTANCE = "RDS_INSTANCE"
    VPC = "VPC"
    SUBNET = "SUBNET"
    SECURITY_GROUP = "SECURITY_GROUP"
    API_GATEWAY = "API_GATEWAY"
    CLOUDTRAIL = "CLOUDTRAIL"
    KMS_KEY = "KMS_KEY"
    INTERNET_GATEWAY = "INTERNET_GATEWAY"
    LOAD_BALANCER = "LOAD_BALANCER"


class EdgeType(str, Enum):
    CAN_ASSUME = "CAN_ASSUME"        # Role assumption
    HAS_POLICY = "HAS_POLICY"        # Policy attachment
    CAN_ACCESS = "CAN_ACCESS"        # Resource access
    NETWORK_CONNECTS = "NETWORK_CONNECTS"  # Network path
    TRUSTS = "TRUSTS"               # Trust relationship
    INHERITS = "INHERITS"           # Permission inheritance
    EXPOSES = "EXPOSES"             # Public exposure


@dataclass
class CloudNode:
    id: str
    node_type: NodeType
    name: str
    arn: Optional[str] = None
    region: str = "us-east-1"
    is_public: bool = False
    risk_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    misconfigurations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "node_type": self.node_type.value,
            "name": self.name,
            "arn": self.arn,
            "region": self.region,
            "is_public": self.is_public,
            "risk_score": self.risk_score,
            "metadata": self.metadata,
            "last_updated": self.last_updated.isoformat(),
            "misconfigurations": self.misconfigurations,
        }


@dataclass
class CloudEdge:
    source_id: str
    target_id: str
    edge_type: EdgeType
    weight: float = 1.0
    permissions: List[str] = field(default_factory=list)
    conditions: Dict[str, Any] = field(default_factory=dict)
    is_exploitable: bool = False

    def to_dict(self) -> Dict:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "weight": self.weight,
            "permissions": self.permissions,
            "conditions": self.conditions,
            "is_exploitable": self.is_exploitable,
        }


class CloudAttackSurfaceGraph:
    """
    Real-time cloud attack surface graph builder.
    Connects to AWS APIs and Neo4j to maintain a live graph
    of all cloud resources and their trust relationships.
    """

    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str,
                 aws_region: str = "us-east-1"):
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_pass = neo4j_pass
        self.aws_region = aws_region
        self.nx_graph = nx.DiGraph()  # In-memory graph for fast traversal
        self._driver: Optional[AsyncDriver] = None
        self._nodes: Dict[str, CloudNode] = {}
        self._edges: List[CloudEdge] = []

    async def connect(self):
        """Initialize Neo4j connection."""
        self._driver = AsyncGraphDatabase.driver(
            self.neo4j_uri,
            auth=(self.neo4j_user, self.neo4j_pass)
        )
        await self._init_schema()
        console.print("[green]✓ CASG connected to Neo4j[/green]")

    async def _init_schema(self):
        """Create Neo4j indexes and constraints."""
        async with self._driver.session() as session:
            queries = [
                "CREATE CONSTRAINT node_id IF NOT EXISTS FOR (n:CloudResource) REQUIRE n.id IS UNIQUE",
                "CREATE INDEX node_type IF NOT EXISTS FOR (n:CloudResource) ON (n.node_type)",
                "CREATE INDEX risk_score IF NOT EXISTS FOR (n:CloudResource) ON (n.risk_score)",
            ]
            for q in queries:
                try:
                    await session.run(q)
                except Exception:
                    pass  # Already exists

    async def scan_aws_infrastructure(self, session_name: str = "aztcse-scan"):
        """
        Full AWS infrastructure scan.
        Discovers all resources and builds the attack surface graph.
        """
        console.print("[bold cyan]🔍 Scanning AWS Infrastructure...[/bold cyan]")
        
        try:
            # Initialize AWS clients
            iam = boto3.client('iam', region_name=self.aws_region)
            ec2 = boto3.client('ec2', region_name=self.aws_region)
            s3 = boto3.client('s3', region_name=self.aws_region)
            
            # Parallel scanning
            await asyncio.gather(
                self._scan_iam_resources(iam),
                self._scan_ec2_resources(ec2),
                self._scan_s3_resources(s3),
                self._scan_network_resources(ec2),
            )
            
            # Build edges after nodes are collected
            await self._build_trust_edges(iam)
            await self._build_network_edges(ec2)
            
            # Persist to Neo4j
            await self._sync_to_neo4j()
            
            console.print(f"[green]✓ Graph built: {len(self._nodes)} nodes, {len(self._edges)} edges[/green]")
            
        except Exception as e:
            logger.warning(f"AWS scan error (running in demo mode): {e}")
            await self._load_demo_graph()

    async def _scan_iam_resources(self, iam_client):
        """Scan all IAM users, roles, policies."""
        try:
            # Users
            paginator = iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    node = CloudNode(
                        id=user['UserId'],
                        node_type=NodeType.IAM_USER,
                        name=user['UserName'],
                        arn=user['Arn'],
                        metadata={
                            'created': user['CreateDate'].isoformat(),
                            'path': user['Path']
                        }
                    )
                    await self._check_user_misconfigs(iam_client, node, user)
                    self._add_node(node)

            # Roles
            paginator = iam_client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    node = CloudNode(
                        id=role['RoleId'],
                        node_type=NodeType.IAM_ROLE,
                        name=role['RoleName'],
                        arn=role['Arn'],
                        metadata={
                            'trust_policy': json.dumps(role.get('AssumeRolePolicyDocument', {})),
                            'path': role['Path']
                        }
                    )
                    await self._check_role_misconfigs(iam_client, node, role)
                    self._add_node(node)

        except Exception as e:
            logger.error(f"IAM scan failed: {e}")

    async def _check_user_misconfigs(self, iam, node: CloudNode, user: dict):
        """Check for common IAM user misconfigurations."""
        try:
            # Check for console access without MFA
            login_profile = None
            try:
                login_profile = iam.get_login_profile(UserName=user['UserName'])
            except Exception:
                pass

            if login_profile:
                mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])
                if not mfa_devices['MFADevices']:
                    node.misconfigurations.append("Console access without MFA enabled")
                    node.risk_score += 0.4

            # Check for old access keys
            keys = iam.list_access_keys(UserName=user['UserName'])
            for key in keys['AccessKeyMetadata']:
                if key['Status'] == 'Active':
                    age_days = (datetime.now(timezone.utc) - key['CreateDate']).days
                    if age_days > 90:
                        node.misconfigurations.append(f"Access key older than 90 days ({age_days} days)")
                        node.risk_score += 0.3

            # Check for admin policies
            attached = iam.list_attached_user_policies(UserName=user['UserName'])
            for policy in attached['AttachedPolicies']:
                if 'Admin' in policy['PolicyName'] or 'FullAccess' in policy['PolicyName']:
                    node.misconfigurations.append(f"Admin policy attached: {policy['PolicyName']}")
                    node.risk_score += 0.5

        except Exception as e:
            logger.debug(f"Misconfiguration check error: {e}")

    async def _check_role_misconfigs(self, iam, node: CloudNode, role: dict):
        """Check for dangerous role trust policies."""
        trust_policy = role.get('AssumeRolePolicyDocument', {})
        statements = trust_policy.get('Statement', [])
        
        for stmt in statements:
            principal = stmt.get('Principal', {})
            if principal == '*' or principal == {"AWS": "*"}:
                node.misconfigurations.append("Role trusted by ANY AWS principal (wildcard trust)")
                node.risk_score += 0.8
            
            # Check for cross-account trust without conditions
            if isinstance(principal, dict):
                aws_principals = principal.get('AWS', [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                for p in aws_principals:
                    if 'root' in p and not stmt.get('Condition'):
                        node.misconfigurations.append("Root cross-account trust without conditions")
                        node.risk_score += 0.6

    async def _scan_ec2_resources(self, ec2_client):
        """Scan EC2 instances."""
        try:
            paginator = ec2_client.get_paginator('describe_instances')
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        if instance['State']['Name'] == 'terminated':
                            continue
                        
                        name = next(
                            (tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'),
                            instance['InstanceId']
                        )
                        
                        node = CloudNode(
                            id=instance['InstanceId'],
                            node_type=NodeType.EC2_INSTANCE,
                            name=name,
                            arn=f"arn:aws:ec2:{self.aws_region}::instance/{instance['InstanceId']}",
                            is_public=bool(instance.get('PublicIpAddress')),
                            metadata={
                                'state': instance['State']['Name'],
                                'type': instance['InstanceType'],
                                'public_ip': instance.get('PublicIpAddress'),
                                'private_ip': instance.get('PrivateIpAddress'),
                                'subnet_id': instance.get('SubnetId'),
                                'vpc_id': instance.get('VpcId'),
                                'security_groups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
                            }
                        )
                        
                        if node.is_public:
                            node.misconfigurations.append("Instance has public IP - exposed to internet")
                            node.risk_score += 0.3
                        
                        self._add_node(node)
        except Exception as e:
            logger.error(f"EC2 scan failed: {e}")

    async def _scan_s3_resources(self, s3_client):
        """Scan S3 buckets for public access and misconfigurations."""
        try:
            response = s3_client.list_buckets()
            for bucket in response['Buckets']:
                node = CloudNode(
                    id=f"s3-{bucket['Name']}",
                    node_type=NodeType.S3_BUCKET,
                    name=bucket['Name'],
                    arn=f"arn:aws:s3:::{bucket['Name']}",
                    metadata={'created': bucket['CreationDate'].isoformat()}
                )
                
                # Check public access
                try:
                    acl = s3_client.get_bucket_acl(Bucket=bucket['Name'])
                    for grant in acl['Grants']:
                        grantee = grant['Grantee']
                        if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            node.is_public = True
                            node.misconfigurations.append(f"S3 bucket is PUBLIC with {grant['Permission']} access")
                            node.risk_score += 0.9 if grant['Permission'] == 'WRITE' else 0.7
                except Exception:
                    pass
                
                # Check versioning
                try:
                    versioning = s3_client.get_bucket_versioning(Bucket=bucket['Name'])
                    if versioning.get('Status') != 'Enabled':
                        node.misconfigurations.append("Versioning not enabled")
                        node.risk_score += 0.1
                except Exception:
                    pass
                
                # Check encryption
                try:
                    s3_client.get_bucket_encryption(Bucket=bucket['Name'])
                except Exception:
                    node.misconfigurations.append("Bucket encryption not configured")
                    node.risk_score += 0.2
                
                self._add_node(node)
        except Exception as e:
            logger.error(f"S3 scan failed: {e}")

    async def _scan_network_resources(self, ec2_client):
        """Scan VPCs, subnets, security groups."""
        try:
            # Security Groups
            response = ec2_client.describe_security_groups()
            for sg in response['SecurityGroups']:
                node = CloudNode(
                    id=sg['GroupId'],
                    node_type=NodeType.SECURITY_GROUP,
                    name=sg.get('GroupName', sg['GroupId']),
                    metadata={
                        'vpc_id': sg['VpcId'],
                        'inbound_rules': len(sg.get('IpPermissions', [])),
                        'outbound_rules': len(sg.get('IpPermissionsEgress', [])),
                    }
                )
                
                # Check for 0.0.0.0/0 inbound
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port = rule.get('FromPort', 'ALL')
                            to_port = rule.get('ToPort', 'ALL')
                            node.misconfigurations.append(
                                f"Open to world: port {from_port}-{to_port} from 0.0.0.0/0"
                            )
                            if from_port in [22, 3389]:  # SSH/RDP
                                node.risk_score += 0.9
                            else:
                                node.risk_score += 0.5
                
                self._add_node(node)
        except Exception as e:
            logger.error(f"Network scan failed: {e}")

    async def _build_trust_edges(self, iam_client):
        """Build trust relationship edges between IAM entities."""
        try:
            # Get all roles and check who can assume them
            for node_id, node in self._nodes.items():
                if node.node_type == NodeType.IAM_ROLE:
                    trust_policy = json.loads(node.metadata.get('trust_policy', '{}'))
                    for stmt in trust_policy.get('Statement', []):
                        if stmt.get('Effect') == 'Allow':
                            principal = stmt.get('Principal', {})
                            aws_principals = []
                            
                            if isinstance(principal, dict):
                                aws_principals = principal.get('AWS', [])
                            elif principal == '*':
                                aws_principals = ['*']
                            
                            if isinstance(aws_principals, str):
                                aws_principals = [aws_principals]
                            
                            for p in aws_principals:
                                # Find matching source node
                                for src_id, src_node in self._nodes.items():
                                    if src_node.arn and src_node.arn in p:
                                        edge = CloudEdge(
                                            source_id=src_id,
                                            target_id=node_id,
                                            edge_type=EdgeType.CAN_ASSUME,
                                            permissions=['sts:AssumeRole'],
                                            is_exploitable=node.risk_score > 0.5
                                        )
                                        self._add_edge(edge)
        except Exception as e:
            logger.error(f"Trust edge build failed: {e}")

    async def _build_network_edges(self, ec2_client):
        """Build network connectivity edges."""
        for node_id, node in self._nodes.items():
            if node.node_type == NodeType.EC2_INSTANCE:
                sgs = node.metadata.get('security_groups', [])
                for sg_id in sgs:
                    if sg_id in self._nodes:
                        edge = CloudEdge(
                            source_id=node_id,
                            target_id=sg_id,
                            edge_type=EdgeType.NETWORK_CONNECTS,
                            weight=0.8
                        )
                        self._add_edge(edge)

    async def _load_demo_graph(self):
        """Load a realistic demo graph when AWS is not configured."""
        console.print("[yellow]⚠ Loading demo infrastructure graph...[/yellow]")
        
        demo_nodes = [
            CloudNode("user-001", NodeType.IAM_USER, "admin-user",
                      "arn:aws:iam::123456789:user/admin-user",
                      risk_score=0.7,
                      misconfigurations=["Console access without MFA", "Access key older than 90 days"]),
            CloudNode("user-002", NodeType.IAM_USER, "dev-user",
                      "arn:aws:iam::123456789:user/dev-user",
                      risk_score=0.2),
            CloudNode("role-001", NodeType.IAM_ROLE, "EC2AdminRole",
                      "arn:aws:iam::123456789:role/EC2AdminRole",
                      risk_score=0.6,
                      misconfigurations=["Wildcard trust policy - assumed by any principal"]),
            CloudNode("role-002", NodeType.IAM_ROLE, "S3ReadRole",
                      "arn:aws:iam::123456789:role/S3ReadRole",
                      risk_score=0.1),
            CloudNode("ec2-001", NodeType.EC2_INSTANCE, "web-server-01",
                      "arn:aws:ec2:us-east-1::instance/i-001",
                      is_public=True, risk_score=0.5,
                      misconfigurations=["Public IP exposed to internet"]),
            CloudNode("ec2-002", NodeType.EC2_INSTANCE, "db-server-01",
                      "arn:aws:ec2:us-east-1::instance/i-002",
                      risk_score=0.3),
            CloudNode("s3-001", NodeType.S3_BUCKET, "company-data-bucket",
                      "arn:aws:s3:::company-data-bucket",
                      is_public=True, risk_score=0.9,
                      misconfigurations=["Bucket is PUBLIC with READ access", "No encryption configured"]),
            CloudNode("s3-002", NodeType.S3_BUCKET, "logs-bucket",
                      "arn:aws:s3:::logs-bucket",
                      risk_score=0.1),
            CloudNode("sg-001", NodeType.SECURITY_GROUP, "web-sg",
                      risk_score=0.6,
                      misconfigurations=["SSH (22) open to 0.0.0.0/0", "RDP (3389) open to 0.0.0.0/0"]),
            CloudNode("sg-002", NodeType.SECURITY_GROUP, "db-sg",
                      risk_score=0.2),
            CloudNode("vpc-001", NodeType.VPC, "main-vpc", risk_score=0.1),
        ]
        
        demo_edges = [
            CloudEdge("user-001", "role-001", EdgeType.CAN_ASSUME, is_exploitable=True,
                      permissions=["sts:AssumeRole"]),
            CloudEdge("user-002", "role-002", EdgeType.CAN_ASSUME,
                      permissions=["sts:AssumeRole"]),
            CloudEdge("role-001", "s3-001", EdgeType.CAN_ACCESS, is_exploitable=True,
                      permissions=["s3:*"]),
            CloudEdge("role-001", "ec2-001", EdgeType.CAN_ACCESS,
                      permissions=["ec2:*"]),
            CloudEdge("ec2-001", "sg-001", EdgeType.NETWORK_CONNECTS),
            CloudEdge("ec2-002", "sg-002", EdgeType.NETWORK_CONNECTS),
            CloudEdge("ec2-001", "s3-001", EdgeType.CAN_ACCESS,
                      permissions=["s3:GetObject", "s3:PutObject"]),
            CloudEdge("sg-001", "sg-002", EdgeType.NETWORK_CONNECTS, weight=0.3),
            CloudEdge("vpc-001", "ec2-001", EdgeType.NETWORK_CONNECTS),
            CloudEdge("vpc-001", "ec2-002", EdgeType.NETWORK_CONNECTS),
        ]
        
        for node in demo_nodes:
            self._add_node(node)
        for edge in demo_edges:
            self._add_edge(edge)
        
        console.print(f"[green]✓ Demo graph: {len(self._nodes)} nodes, {len(self._edges)} edges[/green]")

    def _add_node(self, node: CloudNode):
        """Add node to both in-memory and graph."""
        self._nodes[node.id] = node
        self.nx_graph.add_node(
            node.id,
            **node.to_dict()
        )

    def _add_edge(self, edge: CloudEdge):
        """Add edge to both in-memory and graph."""
        self._edges.append(edge)
        self.nx_graph.add_edge(
            edge.source_id,
            edge.target_id,
            **edge.to_dict()
        )

    async def _sync_to_neo4j(self):
        """Persist graph to Neo4j for persistent storage & querying."""
        if not self._driver:
            return
        
        async with self._driver.session() as session:
            # Clear old data
            await session.run("MATCH (n:CloudResource) DETACH DELETE n")
            
            # Insert nodes
            for node in self._nodes.values():
                await session.run(
                    """
                    CREATE (n:CloudResource {
                        id: $id, node_type: $node_type, name: $name,
                        arn: $arn, is_public: $is_public, risk_score: $risk_score,
                        misconfigurations: $misconfigurations
                    })
                    """,
                    id=node.id,
                    node_type=node.node_type.value,
                    name=node.name,
                    arn=node.arn or "",
                    is_public=node.is_public,
                    risk_score=node.risk_score,
                    misconfigurations=node.misconfigurations
                )
            
            # Insert edges
            for edge in self._edges:
                await session.run(
                    """
                    MATCH (a:CloudResource {id: $src}), (b:CloudResource {id: $tgt})
                    CREATE (a)-[:CONNECTS {
                        edge_type: $edge_type, weight: $weight,
                        is_exploitable: $is_exploitable
                    }]->(b)
                    """,
                    src=edge.source_id,
                    tgt=edge.target_id,
                    edge_type=edge.edge_type.value,
                    weight=edge.weight,
                    is_exploitable=edge.is_exploitable
                )

    def get_high_risk_nodes(self, threshold: float = 0.6) -> List[CloudNode]:
        """Return all nodes above risk threshold."""
        return [n for n in self._nodes.values() if n.risk_score >= threshold]

    def get_public_exposure_paths(self) -> List[List[str]]:
        """Find all paths from public resources to sensitive internal resources."""
        public_nodes = [n.id for n in self._nodes.values() if n.is_public]
        sensitive_nodes = [n.id for n in self._nodes.values() 
                          if n.node_type in [NodeType.RDS_INSTANCE, NodeType.S3_BUCKET] 
                          and not n.is_public]
        
        paths = []
        for src in public_nodes:
            for tgt in sensitive_nodes:
                try:
                    if nx.has_path(self.nx_graph, src, tgt):
                        for path in nx.all_simple_paths(self.nx_graph, src, tgt, cutoff=5):
                            paths.append(path)
                except nx.NetworkXError:
                    pass
        return paths

    def get_privilege_escalation_paths(self) -> List[List[str]]:
        """Find paths that could lead to privilege escalation."""
        regular_users = [n.id for n in self._nodes.values() 
                        if n.node_type == NodeType.IAM_USER and 'admin' not in n.name.lower()]
        admin_roles = [n.id for n in self._nodes.values() 
                      if n.node_type == NodeType.IAM_ROLE and (
                          any('Admin' in m for m in n.misconfigurations) or 
                          n.risk_score > 0.5
                      )]
        
        paths = []
        for src in regular_users:
            for tgt in admin_roles:
                try:
                    if nx.has_path(self.nx_graph, src, tgt):
                        for path in nx.all_simple_paths(self.nx_graph, src, tgt, cutoff=4):
                            paths.append(path)
                except nx.NetworkXError:
                    pass
        return paths

    def get_graph_summary(self) -> Dict:
        """Return comprehensive graph summary."""
        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "public_resources": sum(1 for n in self._nodes.values() if n.is_public),
            "high_risk_resources": len(self.get_high_risk_nodes()),
            "misconfigured_resources": sum(1 for n in self._nodes.values() if n.misconfigurations),
            "node_types": {
                nt.value: sum(1 for n in self._nodes.values() if n.node_type == nt)
                for nt in NodeType
            },
            "avg_risk_score": sum(n.risk_score for n in self._nodes.values()) / max(len(self._nodes), 1),
            "total_misconfigurations": sum(len(n.misconfigurations) for n in self._nodes.values()),
        }

    def print_summary(self):
        """Print rich table summary of graph."""
        summary = self.get_graph_summary()
        
        table = Table(title="🗺️  Cloud Attack Surface Graph Summary", 
                     style="cyan", show_header=True)
        table.add_column("Metric", style="bold white")
        table.add_column("Value", style="yellow")
        
        table.add_row("Total Resources", str(summary['total_nodes']))
        table.add_row("Trust Relationships", str(summary['total_edges']))
        table.add_row("Public Resources", f"[red]{summary['public_resources']}[/red]")
        table.add_row("High Risk Resources", f"[red]{summary['high_risk_resources']}[/red]")
        table.add_row("Misconfigured", f"[orange3]{summary['misconfigured_resources']}[/orange3]")
        table.add_row("Avg Risk Score", f"{summary['avg_risk_score']:.2f}")
        
        console.print(table)

    @property
    def nodes(self) -> Dict[str, CloudNode]:
        return self._nodes

    @property
    def edges(self) -> List[CloudEdge]:
        return self._edges

    async def close(self):
        if self._driver:
            await self._driver.close()
