"""
seed.py - Seed the FalkorDB graph for TEZCATL.

Resets and seeds the designated FalkorDB graph ('prod_graph').
Sets up both the attack topology (ATTACK_STEP) and downstream operational dependencies (DEPENDS_ON)
with revenue_impact_scores for dynamic blast-radius calculation.
"""

import sys
from falkordb import FalkorDB

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


try:
    from config import settings
    FALKORDB_HOST = settings.falkordb_host
    FALKORDB_PORT = settings.falkordb_port
    GRAPH_NAME = settings.falkordb_graph
except Exception:
    import os
    FALKORDB_HOST = os.getenv("FALKORDB_HOST", "127.0.0.1")
    FALKORDB_PORT = int(os.getenv("FALKORDB_PORT", "6379"))
    GRAPH_NAME = os.getenv("FALKORDB_GRAPH", "prod_graph")

# Infrastructure Entity Records
INFRA_NODES = [
    {"id": "ci_runner", "name": "GitHub Actions CI Runner", "kind": "workload", "criticality": "high", "cost": 10, "revenue_impact_score": 0, "status": "compromised"},
    {"id": "runner_host", "name": "Ephemeral Runner Host", "kind": "host", "criticality": "medium", "cost": 9, "revenue_impact_score": 0, "status": "active"},
    {"id": "deploy_token", "name": "Production Deploy Credential", "kind": "credential", "criticality": "high", "cost": 2, "revenue_impact_score": 0, "status": "active"},
    {"id": "production_deploy_role", "name": "Production Deploy IAM Role", "kind": "iam_role", "criticality": "high", "cost": 6, "revenue_impact_score": 0, "status": "active"},
    {"id": "artifact_token", "name": "Artifact Publish Credential", "kind": "credential", "criticality": "high", "cost": 3, "revenue_impact_score": 0, "status": "active"},
    {"id": "artifact_registry", "name": "Private Artifact Registry", "kind": "registry", "criticality": "high", "cost": 7, "revenue_impact_score": 0, "status": "active"},
    {"id": "release_controller", "name": "Production Release Controller", "kind": "service", "criticality": "critical", "cost": 10, "revenue_impact_score": 0, "status": "active"},
    {"id": "signer_role", "name": "Release Signing IAM Role", "kind": "iam_role", "criticality": "critical", "cost": 8, "revenue_impact_score": 0, "status": "active"},
    {"id": "signing_key", "name": "Production Signing Key", "kind": "key", "criticality": "crown_jewel", "cost": 9999, "revenue_impact_score": 0, "status": "active"},
    {"id": "legacy_release_session", "name": "Legacy Release Session", "kind": "session", "criticality": "high", "cost": 4, "revenue_impact_score": 0, "status": "active"},
    {"id": "build_artifact", "name": "Signed Release Artifact", "kind": "artifact", "criticality": "high", "cost": 6, "revenue_impact_score": 0, "status": "active"},
    {"id": "production_cluster", "name": "Production Kubernetes Cluster", "kind": "cluster", "criticality": "critical", "cost": 9, "revenue_impact_score": 0, "status": "active"},
    {"id": "audit_service", "name": "Release Audit Service", "kind": "service", "criticality": "medium", "cost": 5, "revenue_impact_score": 2, "status": "active"},
    {"id": "approval_service", "name": "Release Approval Service", "kind": "service", "criticality": "high", "cost": 5, "revenue_impact_score": 3, "status": "active"},
    {"id": "deployment_manifest", "name": "Production Deployment Manifest", "kind": "artifact", "criticality": "high", "cost": 5, "revenue_impact_score": 0, "status": "active"},
    {"id": "runner_oidc_binding", "name": "Runner OIDC Trust Binding", "kind": "trust_binding", "criticality": "high", "cost": 6, "revenue_impact_score": 0, "status": "active"},
]

# Downstream Business Services for Dynamic Blast-Radius Calculus
DOWNSTREAM_SERVICES = [
    {"id": "checkout_api", "name": "Checkout API", "kind": "service", "criticality": "critical", "cost": 10, "revenue_impact_score": 5, "status": "active"},
    {"id": "billing_worker", "name": "Billing Worker", "kind": "service", "criticality": "high", "cost": 8, "revenue_impact_score": 3, "status": "active"},
    {"id": "release_pipeline", "name": "Release Pipeline", "kind": "service", "criticality": "high", "cost": 6, "revenue_impact_score": 2, "status": "active"},
    {"id": "auth_gateway", "name": "Auth Gateway", "kind": "service", "criticality": "critical", "cost": 10, "revenue_impact_score": 5, "status": "active"},
    {"id": "staging_deployer", "name": "Staging Deployer", "kind": "service", "criticality": "medium", "cost": 4, "revenue_impact_score": 2, "status": "active"},
    {"id": "artifact_publisher", "name": "Artifact Publish Daemon", "kind": "service", "criticality": "medium", "cost": 5, "revenue_impact_score": 3, "status": "active"},
    {"id": "legacy_batch_service", "name": "Legacy Batch Consumer", "kind": "service", "criticality": "medium", "cost": 4, "revenue_impact_score": 4, "status": "active"},
    {"id": "canary_service", "name": "Canary Rollout Service", "kind": "service", "criticality": "high", "cost": 7, "revenue_impact_score": 4, "status": "active"},
    {"id": "binary_attestation", "name": "Binary Attestation Verifier", "kind": "service", "criticality": "high", "cost": 8, "revenue_impact_score": 4, "status": "active"},
]

NODES = INFRA_NODES + DOWNSTREAM_SERVICES
ALL_NODES = NODES

# Directed Attack Edges (Section 5 exact attack graph)
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

# Baseline Infrastructure Operational Dependencies
INFRA_DEPENDENCIES = [
    {"source": "ci_runner", "target": "runner_host", "purpose": "runs_on"},
    {"source": "ci_runner", "target": "runner_oidc_binding", "purpose": "requests_federated_identity"},
    {"source": "release_controller", "target": "build_artifact", "purpose": "consumes_artifact"},
    {"source": "release_controller", "target": "production_cluster", "purpose": "deploys_to"},
    {"source": "release_controller", "target": "audit_service", "purpose": "emits_audit_events"},
    {"source": "release_controller", "target": "approval_service", "purpose": "requires_approval"},
    {"source": "artifact_registry", "target": "deployment_manifest", "purpose": "stores_release_manifest"},
]

# Service Operational Dependencies for Multi-Hop Blast-Radius Graph Traversal
SERVICE_DEPENDENCIES = [
    {"source": "staging_deployer", "target": "deploy_token", "purpose": "uses_deploy_credentials"},
    {"source": "artifact_publisher", "target": "artifact_token", "purpose": "uses_publish_credentials"},
    {"source": "checkout_api", "target": "release_controller", "purpose": "deployed_by_controller"},
    {"source": "billing_worker", "target": "release_controller", "purpose": "orchestrated_by_controller"},
    {"source": "release_pipeline", "target": "release_controller", "purpose": "managed_by_controller"},
    {"source": "legacy_batch_service", "target": "legacy_release_session", "purpose": "consumes_legacy_session"},
    {"source": "release_pipeline", "target": "production_deploy_role", "purpose": "assumes_deploy_role"},
    {"source": "canary_service", "target": "production_deploy_role", "purpose": "assumes_deploy_role"},
    {"source": "artifact_publisher", "target": "artifact_registry", "purpose": "pushes_to_registry"},
    {"source": "canary_service", "target": "artifact_registry", "purpose": "pulls_from_registry"},
    {"source": "binary_attestation", "target": "signer_role", "purpose": "requests_role_signatures"},
    {"source": "canary_service", "target": "signer_role", "purpose": "verifies_signing_role"},
]

DEPENDENCIES = INFRA_DEPENDENCIES + SERVICE_DEPENDENCIES
ALL_DEPENDENCIES = DEPENDENCIES


def seed_single_graph(graph, graph_name: str):
    """Seed an individual FalkorDB graph instance."""
    print(f"Resetting nodes and relationships in '{graph_name}' graph...")
    graph.query("MATCH (n) DETACH DELETE n")

    # 1. Insert Entity nodes using parameterized Cypher query
    node_query = """
    UNWIND $nodes AS node_props
    CREATE (n:Entity {
        id: node_props.id,
        name: node_props.name,
        kind: node_props.kind,
        criticality: node_props.criticality,
        cost: node_props.cost,
        revenue_impact_score: node_props.revenue_impact_score,
        status: node_props.status
    })
    """
    graph.query(node_query, {"nodes": NODES})

    # Label service nodes with :Service label for blast radius queries
    service_label_query = """
    UNWIND $services AS svc
    MATCH (n:Entity {id: svc.id})
    SET n:Service
    """
    graph.query(service_label_query, {"services": DOWNSTREAM_SERVICES})

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
    graph.query(attack_query, {"edges": ATTACK_EDGES})

    # 3. Insert DEPENDS_ON relationships using parameterized Cypher query
    dep_query = """
    UNWIND $deps AS dep_props
    MATCH (src:Entity {id: dep_props.source})
    MATCH (dst:Entity {id: dep_props.target})
    CREATE (src)-[:DEPENDS_ON {
        purpose: dep_props.purpose
    }]->(dst)
    """
    graph.query(dep_query, {"deps": DEPENDENCIES})


def seed_database(host: str = FALKORDB_HOST, port: int = FALKORDB_PORT, graph_name: str = GRAPH_NAME):
    print(f"Connecting to FalkorDB at {host}:{port} for TEZCATL graph '{graph_name}'...")
    try:
        db = FalkorDB(host=host, port=port)
        target_graph = db.select_graph(graph_name)
    except Exception as exc:
        print(f"ERROR: Unable to connect to FalkorDB: {exc}", file=sys.stderr)
        sys.exit(1)

    seed_single_graph(target_graph, graph_name)

    # If target is prod_graph, also seed cutline_demo for backwards compatibility
    if graph_name != "cutline_demo":
        try:
            demo_graph = db.select_graph("cutline_demo")
            seed_single_graph(demo_graph, "cutline_demo")
        except Exception:
            pass

    # Verify counts on target graph
    node_res = target_graph.query("MATCH (n:Entity) RETURN count(n) AS cnt")
    service_res = target_graph.query("MATCH (s:Service) RETURN count(s) AS cnt")
    attack_res = target_graph.query("MATCH ()-[r:ATTACK_STEP]->() RETURN count(r) AS cnt")
    dep_res = target_graph.query("MATCH ()-[r:DEPENDS_ON]->() RETURN count(r) AS cnt")

    node_count = node_res.result_set[0][0]
    service_count = service_res.result_set[0][0]
    attack_count = attack_res.result_set[0][0]
    dep_count = dep_res.result_set[0][0]

    print(f"Found: {node_count} Entity nodes ({service_count} Services), {attack_count} ATTACK_STEP edges, {dep_count} DEPENDS_ON edges")

    if node_count != len(NODES):
        print(f"ERROR: Expected {len(NODES)} Entity nodes, got {node_count}", file=sys.stderr)
        sys.exit(1)
    if attack_count != len(ATTACK_EDGES):
        print(f"ERROR: Expected {len(ATTACK_EDGES)} ATTACK_STEP edges, got {attack_count}", file=sys.stderr)
        sys.exit(1)
    if dep_count != len(DEPENDENCIES):
        print(f"ERROR: Expected {len(DEPENDENCIES)} DEPENDS_ON edges, got {dep_count}", file=sys.stderr)
        sys.exit(1)

    print("SUCCESS: TEZCATL graph seeded and all count assertions passed.")

    # Verify attack path count
    path_query = """
    MATCH p = (src:Entity {id: 'ci_runner'})-[:ATTACK_STEP*1..8]->(target:Entity {criticality: 'crown_jewel'})
    WHERE ALL(r IN relationships(p) WHERE r.active = true)
      AND ALL(n IN nodes(p) WHERE n.status <> 'disabled')
    RETURN [n IN nodes(p) | n.id] AS path, length(p) AS hops
    """
    path_res = target_graph.query(path_query)
    paths = path_res.result_set
    print(f"Found {len(paths)} directed attack paths from ci_runner to crown jewel:")
    for path, hops in paths:
        print(f"  -> Path ({hops} hops): {' -> '.join(path)}")

    if len(paths) != 3:
        print(f"ERROR: Expected 3 paths, got {len(paths)}", file=sys.stderr)
        sys.exit(1)

    print("SUCCESS: TEZCATL graph populated and all node, edge, and path assertions passed.")


if __name__ == "__main__":
    seed_database()
