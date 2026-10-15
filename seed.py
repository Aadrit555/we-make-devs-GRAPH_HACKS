"""
seed.py - Seed the FalkorDB graph for CUTLINE v2.

WARNING: This script is DESTRUCTIVE to the dedicated 'cutline_demo' graph.
It resets all nodes and relationships within 'cutline_demo'.
Other graphs and persistent Docker volumes are unaffected.
"""

import os
import sys
from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()

try:
    from config import settings
    FALKORDB_HOST = settings.falkordb_host
    FALKORDB_PORT = settings.falkordb_port
    GRAPH_NAME = settings.falkordb_graph
except Exception:
    FALKORDB_HOST = os.getenv("FALKORDB_HOST", "127.0.0.1")
    FALKORDB_PORT = int(os.getenv("FALKORDB_PORT", "6379"))
    GRAPH_NAME = os.getenv("FALKORDB_GRAPH", "cutline_demo")

# Section 5 exact entity records
NODES = [
    {"id": "ci_runner", "name": "GitHub Actions CI Runner", "kind": "workload", "criticality": "high", "cost": 10, "status": "compromised"},
    {"id": "runner_host", "name": "Ephemeral Runner Host", "kind": "host", "criticality": "medium", "cost": 9, "status": "active"},
    {"id": "deploy_token", "name": "Production Deploy Credential", "kind": "credential", "criticality": "high", "cost": 2, "status": "active"},
    {"id": "production_deploy_role", "name": "Production Deploy IAM Role", "kind": "iam_role", "criticality": "high", "cost": 6, "status": "active"},
    {"id": "artifact_token", "name": "Artifact Publish Credential", "kind": "credential", "criticality": "high", "cost": 3, "status": "active"},
    {"id": "artifact_registry", "name": "Private Artifact Registry", "kind": "registry", "criticality": "high", "cost": 7, "status": "active"},
    {"id": "release_controller", "name": "Production Release Controller", "kind": "service", "criticality": "critical", "cost": 10, "status": "active"},
    {"id": "signer_role", "name": "Release Signing IAM Role", "kind": "iam_role", "criticality": "critical", "cost": 8, "status": "active"},
    {"id": "signing_key", "name": "Production Signing Key", "kind": "key", "criticality": "crown_jewel", "cost": 9999, "status": "active"},
    {"id": "legacy_release_session", "name": "Legacy Release Session", "kind": "session", "criticality": "high", "cost": 4, "status": "active"},
    {"id": "build_artifact", "name": "Signed Release Artifact", "kind": "artifact", "criticality": "high", "cost": 6, "status": "active"},
    {"id": "production_cluster", "name": "Production Kubernetes Cluster", "kind": "cluster", "criticality": "critical", "cost": 9, "status": "active"},
    {"id": "audit_service", "name": "Release Audit Service", "kind": "service", "criticality": "medium", "cost": 5, "status": "active"},
    {"id": "approval_service", "name": "Release Approval Service", "kind": "service", "criticality": "high", "cost": 5, "status": "active"},
    {"id": "deployment_manifest", "name": "Production Deployment Manifest", "kind": "artifact", "criticality": "high", "cost": 5, "status": "active"},
    {"id": "runner_oidc_binding", "name": "Runner OIDC Trust Binding", "kind": "trust_binding", "criticality": "high", "cost": 6, "status": "active"},
]

# Section 5 exact directed attack edges
ATTACK_EDGES = [
    {"source": "ci_runner", "target": "deploy_token", "mechanism": "Compromised process can access deploy credential", "active": True, "evidence_id": "E-001"},
    {"source": "deploy_token", "target": "production_deploy_role", "mechanism": "Credential permits production role assumption", "active": True, "evidence_id": "E-002"},
    {"source": "production_deploy_role", "target": "release_controller", "mechanism": "Role can invoke production release", "active": True, "evidence_id": "E-003"},
    {"source": "ci_runner", "target": "artifact_token", "mechanism": "Compromised runner can access registry credential", "active": True, "evidence_id": "E-004"},
    {"source": "artifact_token", "target": "artifact_registry", "mechanism": "Credential has artifact publish permission", "active": True, "evidence_id": "E-005"},
    {"source": "artifact_registry", "target": "release_controller", "mechanism": "Controller consumes registry artifacts", "active": True, "evidence_id": "E-006"},
    {"source": "deploy_token", "target": "legacy_release_session", "mechanism": "Credential can reach a legacy release session", "active": True, "evidence_id": "E-007"},
    {"source": "legacy_release_session", "target": "release_controller", "mechanism": "Legacy session can invoke production release", "active": True, "evidence_id": "E-008"},
    {"source": "release_controller", "target": "signer_role", "mechanism": "Release controller can request signing", "active": True, "evidence_id": "E-009"},
    {"source": "signer_role", "target": "signing_key", "mechanism": "Signing role can use production key", "active": True, "evidence_id": "E-010"},
]

# Section 5 exact operational dependencies
DEPENDENCIES = [
    {"source": "ci_runner", "target": "runner_host", "purpose": "runs_on"},
    {"source": "ci_runner", "target": "runner_oidc_binding", "purpose": "requests_federated_identity"},
    {"source": "release_controller", "target": "build_artifact", "purpose": "consumes_artifact"},
    {"source": "release_controller", "target": "production_cluster", "purpose": "deploys_to"},
    {"source": "release_controller", "target": "audit_service", "purpose": "emits_audit_events"},
    {"source": "release_controller", "target": "approval_service", "purpose": "requires_approval"},
    {"source": "artifact_registry", "target": "deployment_manifest", "purpose": "stores_release_manifest"},
]


def seed_database(host: str = FALKORDB_HOST, port: int = FALKORDB_PORT, graph_name: str = GRAPH_NAME):
    print(f"Connecting to FalkorDB at {host}:{port} for graph '{graph_name}'...")
    try:
        db = FalkorDB(host=host, port=port)
        graph = db.select_graph(graph_name)
    except Exception as exc:
        print(f"ERROR: Unable to connect to FalkorDB: {exc}", file=sys.stderr)
        sys.exit(1)

    print("WARNING: Resetting nodes and relationships in 'cutline_demo' graph...")
    try:
        graph.query("MATCH (n) DETACH DELETE n")
    except Exception as exc:
        print(f"ERROR: Failed to clear graph: {exc}", file=sys.stderr)
        sys.exit(1)

    # 1. Insert Entity nodes using parameterized Cypher query
    node_query = """
    UNWIND $nodes AS node_props
    CREATE (n:Entity {
        id: node_props.id,
        name: node_props.name,
        kind: node_props.kind,
        criticality: node_props.criticality,
        cost: node_props.cost,
        status: node_props.status
    })
    """
    print(f"Inserting {len(NODES)} Entity nodes...")
    try:
        graph.query(node_query, {"nodes": NODES})
    except Exception as exc:
        print(f"ERROR: Failed inserting nodes: {exc}", file=sys.stderr)
        sys.exit(1)

    # 2. Insert ATTACK_STEP relationships using parameterized Cypher query
    attack_query = """
    UNWIND $edges AS edge_props
    MATCH (src:Entity {id: edge_props.source})
    MATCH (dst:Entity {id: edge_props.target})
    CREATE (src)-[:ATTACK_STEP {
        mechanism: edge_props.mechanism,
        active: edge_props.active,
        evidence_id: edge_props.evidence_id
    }]->(dst)
    """
    print(f"Inserting {len(ATTACK_EDGES)} ATTACK_STEP relationships...")
    try:
        graph.query(attack_query, {"edges": ATTACK_EDGES})
    except Exception as exc:
        print(f"ERROR: Failed inserting ATTACK_STEP relationships: {exc}", file=sys.stderr)
        sys.exit(1)

    # 3. Insert DEPENDS_ON relationships using parameterized Cypher query
    dep_query = """
    UNWIND $deps AS dep_props
    MATCH (src:Entity {id: dep_props.source})
    MATCH (dst:Entity {id: dep_props.target})
    CREATE (src)-[:DEPENDS_ON {
        purpose: dep_props.purpose
    }]->(dst)
    """
    print(f"Inserting {len(DEPENDENCIES)} DEPENDS_ON relationships...")
    try:
        graph.query(dep_query, {"deps": DEPENDENCIES})
    except Exception as exc:
        print(f"ERROR: Failed inserting DEPENDS_ON relationships: {exc}", file=sys.stderr)
        sys.exit(1)

    # 4. Query and assert counts
    print("Verifying graph counts...")
    node_res = graph.query("MATCH (n:Entity) RETURN count(n) AS cnt")
    attack_res = graph.query("MATCH ()-[r:ATTACK_STEP]->() RETURN count(r) AS cnt")
    dep_res = graph.query("MATCH ()-[r:DEPENDS_ON]->() RETURN count(r) AS cnt")

    node_count = node_res.result_set[0][0]
    attack_count = attack_res.result_set[0][0]
    dep_count = dep_res.result_set[0][0]

    print(f"Found: {node_count} Entity nodes, {attack_count} ATTACK_STEP edges, {dep_count} DEPENDS_ON edges")

    if node_count != 16:
        print(f"ERROR: Expected 16 Entity nodes, got {node_count}", file=sys.stderr)
        sys.exit(1)
    if attack_count != 10:
        print(f"ERROR: Expected 10 ATTACK_STEP edges, got {attack_count}", file=sys.stderr)
        sys.exit(1)
    if dep_count != 7:
        print(f"ERROR: Expected 7 DEPENDS_ON edges, got {dep_count}", file=sys.stderr)
        sys.exit(1)

    print("SUCCESS: Seed graph populated and all count assertions passed.")
    # 5. Query and assert directed attack paths from ci_runner to signing_key (max 8 hops)
    path_query = """
    MATCH p = (src:Entity {id: 'ci_runner'})-[:ATTACK_STEP*1..8]->(target:Entity {criticality: 'crown_jewel'})
    WHERE ALL(r IN relationships(p) WHERE r.active = true)
      AND ALL(n IN nodes(p) WHERE n.status <> 'disabled')
    RETURN [n IN nodes(p) | n.id] AS node_ids, length(p) AS hops
    """
    path_res = graph.query(path_query)
    paths = path_res.result_set
    print(f"Found {len(paths)} directed attack paths from ci_runner to crown jewel:")
    for path_record in paths:
        print(f"  -> Path ({path_record[1]} hops): {' -> '.join(path_record[0])}")

    if len(paths) != 3:
        print(f"ERROR: Expected exactly 3 directed attack paths, got {len(paths)}", file=sys.stderr)
        sys.exit(1)

    for path_record in paths:
        if path_record[0][0] != "ci_runner" or path_record[0][-1] != "signing_key":
            print(f"ERROR: Invalid path endpoints: {path_record[0]}", file=sys.stderr)
            sys.exit(1)

    print("SUCCESS: Seed graph populated and all node, edge, and path assertions passed.")


if __name__ == "__main__":
    seed_database()


