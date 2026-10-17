"""
TEZCATL — Idempotent Database Topology Seed Script (FalkorDB)
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""
from typing import Dict, Any, List
from falkordb import FalkorDB
from backend.config import FALKORDB_HOST, FALKORDB_PORT, PROD_GRAPH

ENTITY_NODES: List[Dict[str, Any]] = [
    {"id": "ci-runner-07", "name": "CI Build Runner 07", "kind": "workload", "criticality": "standard", "status": "active"},
    {"id": "staging-worker-02", "name": "Staging Worker 02", "kind": "workload", "criticality": "standard", "status": "active"},
    {"id": "tok-deploy-alpha", "name": "CI Deploy Token Alpha", "kind": "credential", "criticality": "high", "status": "active"},
    {"id": "tok-artifact-rw", "name": "Artifact Registry RW Token", "kind": "credential", "criticality": "high", "status": "active"},
    {"id": "role-cloud-deployer", "name": "IAM Cloud Deployer Role", "kind": "role", "criticality": "high", "status": "active"},
    {"id": "pkg-registry-core", "name": "Internal Package Registry", "kind": "workload", "criticality": "high", "status": "active"},
    {"id": "release-controller", "name": "Prod Release Controller", "kind": "workload", "criticality": "bottleneck", "status": "active"},
    {"id": "prod-signing-key", "name": "Root Production Signing Key", "kind": "secret", "criticality": "crown_jewel", "status": "active"},
]

SERVICE_NODES: List[Dict[str, Any]] = [
    {"id": "svc-ci-telemetry", "name": "CI Log Aggregator", "weight": 2},
    {"id": "svc-artifact-sync", "name": "Artifact Mirror Sync", "weight": 3},
    {"id": "svc-checkout-api", "name": "Global Checkout API", "weight": 5},
    {"id": "svc-release-pipe", "name": "Zero-Downtime Release Train", "weight": 5},
    {"id": "svc-auth-gateway", "name": "Edge OIDC Gateway", "weight": 4},
]

ATTACK_STEPS: List[Dict[str, Any]] = [
    {"src": "ci-runner-07", "dst": "tok-deploy-alpha", "mech": "ENV_MEM_DUMP", "ev": "EV-101"},
    {"src": "tok-deploy-alpha", "dst": "role-cloud-deployer", "mech": "STS_ASSUME_ROLE", "ev": "EV-102"},
    {"src": "role-cloud-deployer", "dst": "release-controller", "mech": "K8S_EXEC_PRIV", "ev": "EV-103"},
    {"src": "ci-runner-07", "dst": "tok-artifact-rw", "mech": "CACHE_POISON_TOKEN", "ev": "EV-104"},
    {"src": "tok-artifact-rw", "dst": "pkg-registry-core", "mech": "MALICIOUS_WHEEL_PUSH", "ev": "EV-105"},
    {"src": "pkg-registry-core", "dst": "release-controller", "mech": "AUTO_BUILD_TRIGGER", "ev": "EV-106"},
    {"src": "staging-worker-02", "dst": "tok-artifact-rw", "mech": "SHARED_MOUNT_LEAK", "ev": "EV-107"},
    {"src": "release-controller", "dst": "prod-signing-key", "mech": "KMS_DECRYPT_GRANT", "ev": "EV-108"},
]

DEPENDENCIES: List[Dict[str, Any]] = [
    {"svc": "svc-ci-telemetry", "ent": "tok-deploy-alpha"},
    {"svc": "svc-artifact-sync", "ent": "tok-artifact-rw"},
    {"svc": "svc-artifact-sync", "ent": "pkg-registry-core"},
    {"svc": "svc-release-pipe", "ent": "role-cloud-deployer"},
    {"svc": "svc-checkout-api", "ent": "release-controller"},
    {"svc": "svc-release-pipe", "ent": "release-controller"},
    {"svc": "svc-auth-gateway", "ent": "release-controller"},
]


def seed_graph(db: FalkorDB, target_graph: str = PROD_GRAPH) -> Dict[str, Any]:
    """Idempotently populates FalkorDB graph with canonical entities, services, and edges."""
    g = db.select_graph(target_graph)
    g.query("MATCH (n) DETACH DELETE n")

    for ent in ENTITY_NODES:
        g.query(
            "CREATE (:Entity {id: $id, name: $name, kind: $kind, criticality: $criticality, status: $status})",
            params=ent,
        )

    for svc in SERVICE_NODES:
        g.query(
            "CREATE (:Service {id: $id, name: $name, revenue_weight: $weight})",
            params=svc,
        )

    for step in ATTACK_STEPS:
        g.query(
            """
            MATCH (a:Entity {id: $src}), (b:Entity {id: $dst})
            CREATE (a)-[:ATTACK_STEP {mechanism: $mech, evidence_id: $ev, active: true}]->(b)
            """,
            params=step,
        )

    for dep in DEPENDENCIES:
        g.query(
            """
            MATCH (s:Service {id: $svc}), (e:Entity {id: $ent})
            CREATE (s)-[:DEPENDS_ON]->(e)
            """,
            params=dep,
        )

    return {
        "seeded_graph": target_graph,
        "entities": len(ENTITY_NODES),
        "services": len(SERVICE_NODES),
        "attack_steps": len(ATTACK_STEPS),
        "dependencies": len(DEPENDENCIES),
    }


if __name__ == "__main__":
    db = FalkorDB(host=FALKORDB_HOST, port=FALKORDB_PORT)
    res = seed_graph(db, PROD_GRAPH)
    print(f"Successfully seeded '{res['seeded_graph']}': {res['entities']} entities, {res['services']} services.")

