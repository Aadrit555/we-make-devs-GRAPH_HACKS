"""
TEZCATL — Graph-Native Security Containment Agent (FalkorDB)
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
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

# 8 Infrastructure Entity Nodes (Section 5 exact attack topology)
ENTITY_NODES = [
    {"id": "ci-runner-07", "name": "CI Runner 07", "kind": "workload", "criticality": "high", "cost": 10, "revenue_impact_score": 0, "status": "compromised"},
    {"id": "staging-worker-02", "name": "Staging Worker 02", "kind": "workload", "criticality": "medium", "cost": 8, "revenue_impact_score": 0, "status": "active"},
    {"id": "tok-deploy-alpha", "name": "Deploy Credential Alpha", "kind": "credential", "criticality": "high", "cost": 2, "revenue_impact_score": 0, "status": "active"},
    {"id": "tok-artifact-rw", "name": "Artifact RW Token", "kind": "credential", "criticality": "high", "cost": 3, "revenue_impact_score": 0, "status": "active"},
    {"id": "role-cloud-deployer", "name": "Cloud Deployer IAM Role", "kind": "iam_role", "criticality": "high", "cost": 6, "revenue_impact_score": 0, "status": "active"},
    {"id": "pkg-registry-core", "name": "Core Package Registry", "kind": "registry", "criticality": "high", "cost": 7, "revenue_impact_score": 0, "status": "active"},
    {"id": "release-controller", "name": "Production Release Controller", "kind": "service", "criticality": "critical", "cost": 10, "revenue_impact_score": 0, "status": "active"},
    {"id": "prod-signing-key", "name": "Production Signing Key", "kind": "key", "criticality": "crown_jewel", "cost": 9999, "revenue_impact_score": 0, "status": "active"},
]

# 5 Downstream Business Services for Dynamic Service Impact Analysis
SERVICE_NODES = [
    {"id": "checkout-api", "name": "Global Checkout API", "kind": "service", "criticality": "critical", "cost": 10, "revenue_impact_score": 5, "status": "active"},
    {"id": "release-train", "name": "Zero-Downtime Release Train", "kind": "service", "criticality": "critical", "cost": 10, "revenue_impact_score": 5, "status": "active"},
    {"id": "oidc-gateway", "name": "Edge OIDC Gateway", "kind": "service", "criticality": "high", "cost": 8, "revenue_impact_score": 4, "status": "active"},
    {"id": "staging-pipeline", "name": "Staging Build Pipeline", "kind": "service", "criticality": "medium", "cost": 4, "revenue_impact_score": 2, "status": "active"},
    {"id": "artifact-indexer", "name": "Artifact Catalog Indexer", "kind": "service", "criticality": "medium", "cost": 5, "revenue_impact_score": 3, "status": "active"},
]

# Backward compatibility aliases
INFRA_NODES = ENTITY_NODES
DOWNSTREAM_SERVICES = SERVICE_NODES
NODES = ENTITY_NODES
ALL_NODES = ENTITY_NODES

# 8 Directed Attack Step Edges
ATTACK_EDGES = [
    {"source": "ci-runner-07", "target": "tok-deploy-alpha", "mechanism": "Compromised runner accesses deploy token", "active": True, "evidence_id": "E-001"},
    {"source": "ci-runner-07", "target": "tok-artifact-rw", "mechanism": "Compromised runner accesses artifact token", "active": True, "evidence_id": "E-002"},
    {"source": "staging-worker-02", "target": "tok-artifact-rw", "mechanism": "Staging worker accesses artifact token", "active": True, "evidence_id": "E-003"},
    {"source": "tok-deploy-alpha", "target": "role-cloud-deployer", "mechanism": "Deploy token assumes cloud deployer role", "active": True, "evidence_id": "E-004"},
    {"source": "tok-artifact-rw", "target": "pkg-registry-core", "mechanism": "Artifact token publishes to package registry", "active": True, "evidence_id": "E-005"},
    {"source": "role-cloud-deployer", "target": "release-controller", "mechanism": "Cloud deployer invokes release controller", "active": True, "evidence_id": "E-006"},
    {"source": "pkg-registry-core", "target": "release-controller", "mechanism": "Package registry consumed by release controller", "active": True, "evidence_id": "E-007"},
    {"source": "release-controller", "target": "prod-signing-key", "mechanism": "Release controller accesses production signing key", "active": True, "evidence_id": "E-008"},
]

# 7 Reverse Operational Dependencies (Service -> Entity)
DEPENDENCIES = [
    {"source": "checkout-api", "target": "release-controller", "purpose": "deployed_by_controller"},
    {"source": "release-train", "target": "release-controller", "purpose": "managed_by_controller"},
    {"source": "oidc-gateway", "target": "release-controller", "purpose": "orchestrated_by_controller"},
    {"source": "staging-pipeline", "target": "tok-deploy-alpha", "purpose": "uses_deploy_credentials"},
    {"source": "artifact-indexer", "target": "tok-artifact-rw", "purpose": "uses_publish_credentials"},
    {"source": "release-train", "target": "role-cloud-deployer", "purpose": "assumes_deploy_role"},
    {"source": "artifact-indexer", "target": "pkg-registry-core", "purpose": "indexes_registry"},
]

INFRA_DEPENDENCIES = []
SERVICE_DEPENDENCIES = DEPENDENCIES
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
    graph.query(node_query, {"nodes": ENTITY_NODES})

    # 2. Insert Service nodes using parameterized Cypher query
    service_query = """
    UNWIND $services AS svc
    CREATE (s:Service {
        id: svc.id,
        name: svc.name,
        kind: svc.kind,
        criticality: svc.criticality,
        cost: svc.cost,
        revenue_impact_score: svc.revenue_impact_score,
        status: svc.status
    })
    """
    graph.query(service_query, {"services": SERVICE_NODES})

    # 3. Insert ATTACK_STEP relationships using parameterized Cypher query
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

    # 4. Insert DEPENDS_ON relationships using parameterized Cypher query
    dep_query = """
    UNWIND $deps AS dep_props
    MATCH (src:Service {id: dep_props.source})
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

    # Verify counts on target graph
    node_res = target_graph.query("MATCH (n:Entity) RETURN count(n) AS cnt")
    service_res = target_graph.query("MATCH (s:Service) RETURN count(s) AS cnt")
    attack_res = target_graph.query("MATCH ()-[r:ATTACK_STEP]->() RETURN count(r) AS cnt")
    dep_res = target_graph.query("MATCH ()-[r:DEPENDS_ON]->() RETURN count(r) AS cnt")

    node_count = node_res.result_set[0][0]
    service_count = service_res.result_set[0][0]
    attack_count = attack_res.result_set[0][0]
    dep_count = dep_res.result_set[0][0]

    print(f"Found: {node_count} Entity nodes, {service_count} Service nodes, {attack_count} ATTACK_STEP edges, {dep_count} DEPENDS_ON edges")

    if node_count != len(ENTITY_NODES):
        print(f"ERROR: Expected {len(ENTITY_NODES)} Entity nodes, got {node_count}", file=sys.stderr)
        sys.exit(1)
    if service_count != len(SERVICE_NODES):
        print(f"ERROR: Expected {len(SERVICE_NODES)} Service nodes, got {service_count}", file=sys.stderr)
        sys.exit(1)
    if attack_count != len(ATTACK_EDGES):
        print(f"ERROR: Expected {len(ATTACK_EDGES)} ATTACK_STEP edges, got {attack_count}", file=sys.stderr)
        sys.exit(1)
    if dep_count != len(DEPENDENCIES):
        print(f"ERROR: Expected {len(DEPENDENCIES)} DEPENDS_ON edges, got {dep_count}", file=sys.stderr)
        sys.exit(1)

    print("SUCCESS: TEZCATL graph seeded and all count assertions passed.")

    # Verify attack path count from ci-runner-07
    path_query = """
    MATCH p = (src:Entity {id: 'ci-runner-07'})-[:ATTACK_STEP*1..8]->(target:Entity {criticality: 'crown_jewel'})
    WHERE ALL(r IN relationships(p) WHERE r.active = true)
      AND ALL(n IN nodes(p) WHERE n.status <> 'disabled' AND n.status <> 'isolated')
    RETURN [n IN nodes(p) | n.id] AS path, length(p) AS hops
    """
    path_res = target_graph.query(path_query)
    paths = path_res.result_set
    print(f"Found {len(paths)} directed attack paths from ci-runner-07 to crown jewel:")
    for path, hops in paths:
        print(f"  -> Path ({hops} hops): {' -> '.join(path)}")

    if len(paths) != 2:
        print(f"ERROR: Expected 2 paths from ci-runner-07, got {len(paths)}", file=sys.stderr)
        sys.exit(1)

    # Verify attack path count from staging-worker-02
    staging_path_query = """
    MATCH p = (src:Entity {id: 'staging-worker-02'})-[:ATTACK_STEP*1..8]->(target:Entity {criticality: 'crown_jewel'})
    WHERE ALL(r IN relationships(p) WHERE r.active = true)
      AND ALL(n IN nodes(p) WHERE n.status <> 'disabled' AND n.status <> 'isolated')
    RETURN [n IN nodes(p) | n.id] AS path, length(p) AS hops
    """
    staging_paths = target_graph.query(staging_path_query).result_set
    print(f"Found {len(staging_paths)} directed attack paths from staging-worker-02 to crown jewel:")
    for path, hops in staging_paths:
        print(f"  -> Path ({hops} hops): {' -> '.join(path)}")

    if len(staging_paths) != 1:
        print(f"ERROR: Expected 1 path from staging-worker-02, got {len(staging_paths)}", file=sys.stderr)
        sys.exit(1)

    print("SUCCESS: TEZCATL graph populated and all node, edge, and path assertions passed.")


if __name__ == "__main__":
    seed_database()
