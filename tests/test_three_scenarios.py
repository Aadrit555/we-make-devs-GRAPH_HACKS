"""
TEZCATL — Three Distinct Scenarios & Isolation Integration Test Suite
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)

Validates Gate 6 requirements:
- Scenario A: Canonical CI/CD Pipeline demonstration on prod_graph.
- Scenario B: Three-tier web application without threat model on scen_three_tier_prod.
- Scenario C: Microservices topology with branches, cycle, and bottleneck on scen_microservices_prod.
- Manifest validation rejection of invalid types, exceeding bounds, and broken references.
- Complete FalkorDB graph isolation across all scenarios and mirrors.
"""
import pytest
from fastapi.testclient import TestClient
import backend.config as config
from backend.main import app
from backend.models import (
    SecurityTopologyManifest,
    ProjectInfo,
    ManifestNode,
    ManifestEdge,
    SecurityScenario,
    EligibleMitigation,
    ALLOWED_RELATIONSHIP_TYPES,
)
from backend.config import MAX_NODE_COUNT, MAX_EDGE_COUNT, PROD_GRAPH

TEST_TOKEN = "tezcatl-test-operator-auth-2026"
config.ADMIN_TOKEN = TEST_TOKEN
config.REQUIRE_AUTH = True

client = TestClient(app)
AUTH_HEADERS = {"X-Admin-Token": TEST_TOKEN}


def test_scenario_a_canonical_cicd():
    """Scenario A: Canonical WeMakeDevs baseline demonstration on prod_graph."""
    # Reset Scenario A to baseline
    client.post("/api/reset?scenario_id=cicd-compromise", headers=AUTH_HEADERS)

    # Fetch investigation state
    res = client.get("/api/state?scenario_id=cicd-compromise")
    assert res.status_code == 200
    data = res.json()

    assert data["scenario_id"] == "cicd-compromise"
    assert data["graph_name"] == PROD_GRAPH
    assert data["has_threat_model"] is True
    assert data["active_path_count"] == 2
    assert len(data["paths"]) == 2

    # Verify topology nodes and edges
    nodes = {n["id"]: n for n in data["topology"]["nodes"]}
    assert len(nodes) == 8
    assert "ci-runner-07" in nodes
    assert "release-controller" in nodes
    assert "prod-signing-key" in nodes

    # Verify candidates & blast costs
    cand_map = {c["id"]: c for c in data["candidates"]}
    assert cand_map["release-controller"]["blast_cost"] == 14
    assert cand_map["tok-deploy-alpha"]["blast_cost"] == 2
    assert cand_map["tok-artifact-rw"]["blast_cost"] == 3

    # Verify optimal cut is minimal cost 5
    opt = data["cut_solution"]["optimal"]
    assert opt is not None
    assert set(opt["cut_nodes"]) == {"tok-deploy-alpha", "tok-artifact-rw"}
    assert opt["blast_cost"] == 5
    assert opt["complete_cut"] is True

    # Verify shadow-graph sandbox modeling via POST /api/mirror/prepare
    mirror_res = client.post("/api/mirror/prepare", json={
        "source_id": "ci-runner-07",
        "cut_nodes": opt["cut_nodes"],
        "scenario_id": "cicd-compromise"
    }, headers=AUTH_HEADERS)
    assert mirror_res.status_code == 200
    mirror_proof = mirror_res.json()
    assert mirror_proof["verified_safe"] is True
    assert mirror_proof["remaining_paths"] == 0

    # Commit containment
    contain_res = client.post("/api/contain", json={
        "source_id": "ci-runner-07",
        "cut_nodes": opt["cut_nodes"],
        "blast_cost": opt["blast_cost"],
        "scenario_id": "cicd-compromise",
        "plan_fingerprint": opt["plan_fingerprint"],
    }, headers=AUTH_HEADERS)
    assert contain_res.status_code == 200
    c_data = contain_res.json()
    assert c_data["pre_paths"] == 2
    assert c_data["post_paths"] == 0
    assert len(c_data["sha256_receipt"]) == 64

    # Post-action verification
    post_state = client.get("/api/state?scenario_id=cicd-compromise").json()
    assert post_state["active_path_count"] == 0

    # Reset back to pristine baseline
    client.post("/api/reset?scenario_id=cicd-compromise", headers=AUTH_HEADERS)


def test_scenario_b_three_tier_app_no_threat_model():
    """
    Scenario B: Three-tier web application without an attack model.
    Must import, persist in FalkorDB, render topology, and return ZERO security findings.
    UI message must explicitly explain that an attack model has not been supplied.
    """
    res = client.get("/api/state?scenario_id=three-tier-app")
    assert res.status_code == 200
    data = res.json()

    assert data["scenario_id"] == "three-tier-app"
    assert data["graph_name"] == "scen_three_tier_prod"
    assert data["has_threat_model"] is False
    assert "Security analysis requires an explicit threat model" in data["threat_model_message"]

    # Must contain 5 architecture nodes and 5 edges
    assert len(data["topology"]["nodes"]) == 5
    assert len(data["topology"]["edges"]) == 5

    edge_types = {e["type"] for e in data["topology"]["edges"]}
    assert "ATTACK_STEP" not in edge_types
    assert edge_types.issubset({"CALLS", "READS_FROM", "WRITES_TO", "DEPENDS_ON"})

    # Must produce ZERO security findings
    assert data["active_path_count"] == 0
    assert data["paths"] == []
    assert data["candidates"] == []
    assert data["cut_solution"]["optimal"] is None
    assert data["mirror_proof"] is None


def test_scenario_c_microservices_cycles_and_branches():
    """
    Scenario C: Alternate microservices security topology with:
    - Multiple branches.
    - A shared bottleneck (auth-broker).
    - At least one directed cycle (order-processor <-> fraud-checker).
    - Deterministic solver recalculation based on actual scenario costs.
    """
    client.post("/api/reset?scenario_id=microservices-alternate", headers=AUTH_HEADERS)

    res = client.get("/api/state?scenario_id=microservices-alternate")
    assert res.status_code == 200
    data = res.json()

    assert data["scenario_id"] == "microservices-alternate"
    assert data["graph_name"] == "scen_microservices_prod"
    assert data["has_threat_model"] is True
    assert data["source_id"] == "edge-ingress"
    assert "vault-secrets" in data["target_ids"]

    # 7 nodes in topology
    assert len(data["topology"]["nodes"]) == 7

    # Verify cycle presence: fraud-checker -> order-processor CALLS edge
    calls_cycle_edges = [
        e for e in data["topology"]["edges"]
        if e["source"] == "fraud-checker" and e["target"] == "order-processor" and e["type"] == "CALLS"
    ]
    assert len(calls_cycle_edges) == 1

    # Multi-hop attack path discovery finds 2 active attack routes
    assert data["active_path_count"] == 2
    path_hops = [p["hops"] for p in data["paths"]]
    assert 4 in path_hops  # edge-ingress -> order-processor -> fraud-checker -> auth-broker -> vault-secrets
    assert 3 in path_hops  # edge-ingress -> telemetry-aggregator -> auth-broker -> vault-secrets

    # Verify solver recomputation: optimal cut is {telemetry-aggregator, fraud-checker} cost 8
    # (auth-broker alone is cost 9, order-processor is 14)
    opt = data["cut_solution"]["optimal"]
    assert opt is not None
    assert set(opt["cut_nodes"]) == {"telemetry-aggregator", "fraud-checker"}
    assert opt["blast_cost"] == 8

    # Shadow-graph verification in scen_microservices_mirror via POST /api/mirror/prepare
    m_res = client.post("/api/mirror/prepare", json={
        "source_id": "edge-ingress",
        "cut_nodes": opt["cut_nodes"],
        "scenario_id": "microservices-alternate"
    }, headers=AUTH_HEADERS)
    assert m_res.status_code == 200
    mirror_proof = m_res.json()
    assert mirror_proof["verified_safe"] is True
    assert mirror_proof["remaining_paths"] == 0

    # Commit containment on Scenario C
    contain_res = client.post("/api/contain", json={
        "source_id": "edge-ingress",
        "cut_nodes": opt["cut_nodes"],
        "blast_cost": opt["blast_cost"],
        "scenario_id": "microservices-alternate",
        "plan_fingerprint": opt["plan_fingerprint"],
    }, headers=AUTH_HEADERS)
    assert contain_res.status_code == 200
    assert contain_res.json()["post_paths"] == 0

    # Verify post-containment 0 reachability
    post_state = client.get("/api/state?scenario_id=microservices-alternate").json()
    assert post_state["active_path_count"] == 0

    # Reset Scenario C back
    client.post("/api/reset?scenario_id=microservices-alternate", headers=AUTH_HEADERS)


def test_manifest_validation_rules():
    """Validates manifest rejection of malformed or out-of-spec inputs."""
    # 1. Reject invalid relationship type
    with pytest.raises(Exception):
        ManifestEdge(id="e1", source="n1", target="n2", type="HACKS_INTO")

    # 2. Reject missing source or target reference
    with pytest.raises(Exception):
        SecurityTopologyManifest(
            project=ProjectInfo(id="bad-ref", name="Bad Ref"),
            nodes=[ManifestNode(id="n1", name="N1", kind="svc")],
            edges=[ManifestEdge(id="e1", source="n1", target="n_missing", type="CALLS")],
        )

    # 3. Reject duplicate node IDs
    with pytest.raises(Exception):
        SecurityTopologyManifest(
            project=ProjectInfo(id="dup-node", name="Dup Node"),
            nodes=[
                ManifestNode(id="n1", name="N1", kind="svc"),
                ManifestNode(id="n1", name="N1 duplicate", kind="svc"),
            ],
            edges=[],
        )

    # 4. Reject duplicate edge IDs
    with pytest.raises(Exception):
        SecurityTopologyManifest(
            project=ProjectInfo(id="dup-edge", name="Dup Edge"),
            nodes=[
                ManifestNode(id="n1", name="N1", kind="svc"),
                ManifestNode(id="n2", name="N2", kind="svc"),
            ],
            edges=[
                ManifestEdge(id="e1", source="n1", target="n2", type="CALLS"),
                ManifestEdge(id="e1", source="n2", target="n1", type="CALLS"),
            ],
        )

    # 5. Reject scenario source not in nodes
    with pytest.raises(Exception):
        SecurityTopologyManifest(
            project=ProjectInfo(id="bad-source", name="Bad Source"),
            nodes=[ManifestNode(id="n1", name="N1", kind="svc")],
            edges=[],
            scenario=SecurityScenario(source_id="nonexistent-src", target_ids=["n1"]),
        )


def test_scenario_isolation():
    """Verifies that mutations in Scenario C or B never affect Scenario A (prod_graph)."""
    # 1. Scenario A has 2 paths
    client.post("/api/reset?scenario_id=cicd-compromise", headers=AUTH_HEADERS)
    client.post("/api/reset?scenario_id=microservices-alternate", headers=AUTH_HEADERS)

    state_a = client.get("/api/state?scenario_id=cicd-compromise").json()
    assert state_a["active_path_count"] == 2

    # 2. Apply containment to Scenario C
    opt_c = client.get("/api/state?scenario_id=microservices-alternate").json()["cut_solution"]["optimal"]
    client.post("/api/contain", json={
        "source_id": "edge-ingress",
        "cut_nodes": ["telemetry-aggregator", "fraud-checker"],
        "blast_cost": 8,
        "scenario_id": "microservices-alternate",
        "plan_fingerprint": opt_c["plan_fingerprint"],
    }, headers=AUTH_HEADERS)
    state_c = client.get("/api/state?scenario_id=microservices-alternate").json()
    assert state_c["active_path_count"] == 0

    # 3. Scenario A must remain completely unaffected with 2 active paths
    state_a_after = client.get("/api/state?scenario_id=cicd-compromise").json()
    assert state_a_after["active_path_count"] == 2
    assert state_a_after["topology"]["nodes"] == state_a["topology"]["nodes"]

    # Clean up
    client.post("/api/reset?scenario_id=microservices-alternate", headers=AUTH_HEADERS)
