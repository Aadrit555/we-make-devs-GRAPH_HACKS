"""
TEZCATL — Hardened Test Suite for FalkorDB Graph Containment Engine
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.config import ADMIN_TOKEN

client = TestClient(app)
AUTH_HEADERS = {"X-Tezcatl-Auth": ADMIN_TOKEN}


@pytest.fixture(autouse=True)
def ensure_clean_synthetic_state():
    """Confines tests to isolated synthetic demo database state."""
    res = client.post("/api/reset", headers=AUTH_HEADERS)
    assert res.status_code == 200


def test_health_endpoint_connectivity():
    """Verify /api/health performs live FalkorDB query and reports readiness."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HEALTHY"
    assert data["database"] == "FalkorDB Connected"
    assert data["entity_count"] == 8
    assert data["service_count"] == 5
    assert "latency_ms" in data


def test_unauthenticated_state_mutations_rejected():
    """Verify destructive/state-changing endpoints reject unauthenticated calls with 401."""
    # 1. Reset without auth
    r1 = client.post("/api/reset")
    assert r1.status_code == 401, f"Expected 401 for unauthenticated reset, got {r1.status_code}"

    # 2. Bypass mutation without auth
    r2 = client.post("/api/mutate/bypass", json={"source_id": "ci-runner-07"})
    assert r2.status_code == 401, f"Expected 401 for unauthenticated bypass, got {r2.status_code}"

    # 3. Containment without auth
    r3 = client.post("/api/contain", json={"source_id": "ci-runner-07"})
    assert r3.status_code == 401, f"Expected 401 for unauthenticated contain, got {r3.status_code}"

    # 4. Invalid auth token
    r4 = client.post("/api/reset", headers={"X-Tezcatl-Auth": "invalid-token-xyz"})
    assert r4.status_code == 401


def test_authenticated_reset_seeds_synthetic_graph():
    """Verify authenticated reset initializes synthetic topology with 8 entities and 8 edges."""
    state = client.get("/api/state?source_id=ci-runner-07").json()
    assert len(state["topology"]["nodes"]) == 8
    assert len(state["topology"]["edges"]) == 8
    crit_types = {n["criticality"] for n in state["topology"]["nodes"]}
    assert "crown_jewel" in crit_types


def test_multi_hop_variable_length_discovery():
    """Verify multi-hop (*1..8) traversals discover distinct routes to crown jewels."""
    s_ci = client.get("/api/state?source_id=ci-runner-07").json()
    assert s_ci["active_path_count"] == 2
    for p in s_ci["paths"]:
        assert p["hops"] >= 2
        assert p["nodes"][-1]["id"] == "prod-signing-key"

    s_staging = client.get("/api/state?source_id=staging-worker-02").json()
    assert s_staging["active_path_count"] == 1


def test_native_betweenness_centrality_and_costs():
    """Verify native algo.betweenness calculation and reverse DEPENDS_ON service impact."""
    state = client.get("/api/state?source_id=ci-runner-07").json()
    cand_map = {c["id"]: c for c in state["candidates"]}

    # Choke point centrality
    assert cand_map["release-controller"]["centrality"] > 0.0
    assert cand_map["release-controller"]["blast_cost"] == 14
    assert cand_map["tok-deploy-alpha"]["blast_cost"] == 2
    assert cand_map["tok-artifact-rw"]["blast_cost"] == 3


def test_combinatorial_solver_and_optimality_scope():
    """Verify solver candidate limits, search scope, and global optimality declaration."""
    state = client.get("/api/state?source_id=ci-runner-07").json()
    sol = state["cut_solution"]
    opt = sol["optimal"]

    assert opt is not None
    assert set(opt["cut_nodes"]) == {"tok-deploy-alpha", "tok-artifact-rw"}
    assert opt["blast_cost"] == 5
    assert opt["complete_cut"] is True

    # Check optimality bounds
    assert sol["is_exhaustive"] is True
    assert sol["optimality_scope"] == "GLOBAL_EXHAUSTIVE"
    assert sol["candidate_count"] <= 8


def test_shadow_graph_sandbox_isolation():
    """Verify shadow mirror tezcatl_mirror isolates cut nodes while prod_graph remains untouched."""
    state = client.get("/api/state?source_id=ci-runner-07").json()
    proof = state["mirror_proof"]

    assert proof is not None
    assert proof["mirror_graph"] == "tezcatl_mirror"
    assert proof["remaining_paths"] == 0
    assert proof["verified_safe"] is True

    # Verify prod_graph was untouched by shadow simulation
    prod_state = client.get("/api/state?source_id=ci-runner-07").json()
    assert prod_state["active_path_count"] == 2


def test_live_bypass_mutation_and_dynamic_solver_adaptation():
    """Verify injecting bypass edge EV-999 scales paths and dynamically shifts optimal cut."""
    # Inject bypass
    mut = client.post("/api/mutate/bypass", json={"source_id": "ci-runner-07"}, headers=AUTH_HEADERS)
    assert mut.status_code == 200

    state = client.get("/api/state?source_id=ci-runner-07").json()
    assert state["active_path_count"] == 3

    opt = state["cut_solution"]["optimal"]
    assert opt["cut_nodes"] == ["release-controller"]
    assert opt["blast_cost"] == 14


def test_server_side_validated_containment_and_audit_receipt():
    """Verify server recomputes cut, validates post_paths==0, and commits SHA-256 receipt."""
    # Even if caller passes fake node or spoofed blast_cost, server recomputes real plan
    res = client.post(
        "/api/contain",
        json={"source_id": "ci-runner-07", "cut_nodes": ["fake-node"], "blast_cost": 999},
        headers=AUTH_HEADERS,
    )
    assert res.status_code == 200
    rec = res.json()
    assert rec["pre_paths"] == 2
    assert rec["post_paths"] == 0
    # Server overrode with true optimal cut nodes and real blast cost
    assert set(rec["severed_nodes"]) == {"tok-deploy-alpha", "tok-artifact-rw"}
    assert rec["blast_cost"] == 5
    assert rec["status"] == "CONTAINED_AND_VERIFIED"
    assert len(rec["sha256_receipt"]) == 64

    # Confirm live graph has 0 active paths
    post_state = client.get("/api/state?source_id=ci-runner-07").json()
    assert post_state["active_path_count"] == 0


def test_containment_refusal_when_paths_already_contained():
    """Verify containment request is refused if no active attack paths exist."""
    # First containment
    client.post("/api/contain", json={"source_id": "ci-runner-07"}, headers=AUTH_HEADERS)

    # Second containment when already contained
    res = client.post("/api/contain", json={"source_id": "ci-runner-07"}, headers=AUTH_HEADERS)
    assert res.status_code == 400
    assert "No active attack paths detected" in res.json()["detail"]
