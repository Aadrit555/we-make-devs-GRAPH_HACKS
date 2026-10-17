"""
TEZCATL — Live End-to-End Feature Verification Against FalkorDB
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""
import pytest
from fastapi.testclient import TestClient
import backend.config as config
from backend.main import app

TEST_TOKEN = "tezcatl-test-operator-auth-2026"
config.ADMIN_TOKEN = TEST_TOKEN
config.REQUIRE_AUTH = True

client = TestClient(app)
AUTH_HEADERS = {"X-Admin-Token": TEST_TOKEN}


def test_unauthenticated_mutations_rejected_401():
    """Validates that all state-mutating endpoints reject unauthenticated or forged requests."""
    # 1. Missing token
    r_reset = client.post("/api/reset")
    assert r_reset.status_code == 401, f"Expected 401, got {r_reset.status_code}"

    r_contain = client.post("/api/contain", json={
        "source_id": "ci-runner-07",
        "cut_nodes": ["tok-deploy-alpha"],
        "blast_cost": 2,
    })
    assert r_contain.status_code == 401

    r_bypass = client.post("/api/mutate/bypass", json={"source_id": "ci-runner-07"})
    assert r_bypass.status_code == 401

    r_mirror = client.post("/api/mirror/prepare", json={
        "source_id": "ci-runner-07",
        "cut_nodes": ["tok-deploy-alpha"],
    })
    assert r_mirror.status_code == 401

    # 2. Invalid token
    bad_headers = {"X-Admin-Token": "invalid-forged-token-xyz"}
    r_bad = client.post("/api/reset", headers=bad_headers)
    assert r_bad.status_code == 401


def test_stale_plan_fingerprint_rejected_409():
    """Validates that committing a plan with a stale fingerprint fails with 409 Conflict."""
    # Reset to baseline
    client.post("/api/reset?scenario_id=cicd-compromise", headers=AUTH_HEADERS)

    # Fetch initial state and fingerprint
    s_init = client.get("/api/state?scenario_id=cicd-compromise").json()
    init_plan = s_init["cut_solution"]["optimal"]
    assert init_plan is not None
    init_fingerprint = init_plan["plan_fingerprint"]

    # Adversary injects bypass edge, changing topology
    client.post("/api/mutate/bypass", json={"source_id": "ci-runner-07", "scenario_id": "cicd-compromise"}, headers=AUTH_HEADERS)

    # Attempt to commit old plan using stale fingerprint
    res_stale = client.post("/api/contain", json={
        "source_id": "ci-runner-07",
        "cut_nodes": init_plan["cut_nodes"],
        "blast_cost": init_plan["blast_cost"],
        "scenario_id": "cicd-compromise",
        "plan_fingerprint": init_fingerprint,
    }, headers=AUTH_HEADERS)

    assert res_stale.status_code == 409, f"Expected 409 Conflict on stale plan, got {res_stale.status_code}: {res_stale.text}"
    assert "STALE_PLAN_DETECTED" in res_stale.json()["detail"]

    # Clean reset
    client.post("/api/reset?scenario_id=cicd-compromise", headers=AUTH_HEADERS)


def test_end_to_end_falkordb_suite():
    """Live 6-feature verification against FalkorDB with zero simulation."""
    print("\n" + "=" * 78)
    print("TEZCATL // LIVE 6-FEATURE FALKORDB VERIFICATION SUITE")
    print("=" * 78)

    # 1. Reset & Verify Topology
    r_reset = client.post("/api/reset?scenario_id=cicd-compromise", headers=AUTH_HEADERS)
    assert r_reset.status_code == 200
    s1 = client.get("/api/state?source_id=ci-runner-07&scenario_id=cicd-compromise").json()
    assert len(s1["topology"]["nodes"]) == 8, "Expected 8 :Entity nodes in FalkorDB"
    assert len(s1["topology"]["edges"]) == 8, "Expected 8 :ATTACK_STEP edges in FalkorDB"
    print(f"[PASS] Feature 1 (Live Topology): {len(s1['topology']['nodes'])} Entities, {len(s1['topology']['edges'])} Edges")

    # 2. Multi-Hop Path Discovery (*1..8)
    assert s1["active_path_count"] == 2, f"Expected 2 paths, got {s1['active_path_count']}"
    s_staging = client.get("/api/state?source_id=staging-worker-02&scenario_id=cicd-compromise").json()
    assert s_staging["active_path_count"] == 1, f"Expected 1 path for staging-worker-02, got {s_staging['active_path_count']}"
    print(f"[PASS] Feature 2 (Multi-Hop *1..8): ci-runner-07={s1['active_path_count']} paths | staging-worker-02={s_staging['active_path_count']} path")

    # 3. Centrality & Reverse :DEPENDS_ON Service Impact
    cand_map = {c["id"]: c for c in s1["candidates"]}
    assert cand_map["release-controller"]["blast_cost"] == 14
    assert cand_map["tok-deploy-alpha"]["blast_cost"] == 2
    assert cand_map["tok-artifact-rw"]["blast_cost"] == 3
    print(f"[PASS] Feature 3 (Service Impact): release-controller=14, tok-deploy-alpha=2, tok-artifact-rw=3")

    # 4. Minimum-Cut Solver & Explicit Shadow-Graph Sandbox (tezcatl_mirror)
    opt = s1["cut_solution"]["optimal"]
    assert set(opt["cut_nodes"]) == {"tok-deploy-alpha", "tok-artifact-rw"}
    assert opt["blast_cost"] == 5

    m_res = client.post("/api/mirror/prepare", json={
        "source_id": "ci-runner-07",
        "cut_nodes": opt["cut_nodes"],
        "scenario_id": "cicd-compromise",
    }, headers=AUTH_HEADERS)
    assert m_res.status_code == 200
    mirror_proof = m_res.json()
    assert mirror_proof["remaining_paths"] == 0
    assert mirror_proof["verified_safe"] is True
    print(f"[PASS] Feature 4 (Shadow Mirror): Cut {opt['cut_nodes']} (Cost=5) -> 0 paths in tezcatl_mirror while prod_graph has 2")

    # 5. Live Bypass Edge Injection (EV-999)
    client.post("/api/mutate/bypass", json={"source_id": "ci-runner-07", "scenario_id": "cicd-compromise"}, headers=AUTH_HEADERS)
    s_bypass = client.get("/api/state?source_id=ci-runner-07&scenario_id=cicd-compromise").json()
    assert s_bypass["active_path_count"] == 3, "Expected 3 paths after bypass injection"
    opt_bypass = s_bypass["cut_solution"]["optimal"]
    assert opt_bypass["cut_nodes"] == ["release-controller"]
    assert opt_bypass["blast_cost"] == 14

    m_bypass = client.post("/api/mirror/prepare", json={
        "source_id": "ci-runner-07",
        "cut_nodes": opt_bypass["cut_nodes"],
        "scenario_id": "cicd-compromise",
    }, headers=AUTH_HEADERS)
    assert m_bypass.status_code == 200
    assert m_bypass.json()["remaining_paths"] == 0
    print(f"[PASS] Feature 5 (Live Bypass EV-999): Paths jumped 2->3 | Solver shifted cut to {opt_bypass['cut_nodes']} (Cost=14)")

    # 6. Production Containment Commit & SHA-256 Receipt
    client.post("/api/reset?scenario_id=cicd-compromise", headers=AUTH_HEADERS)
    s_fresh = client.get("/api/state?source_id=ci-runner-07&scenario_id=cicd-compromise").json()
    fresh_plan = s_fresh["cut_solution"]["optimal"]

    c_res = client.post(
        "/api/contain",
        json={
            "source_id": "ci-runner-07",
            "cut_nodes": fresh_plan["cut_nodes"],
            "blast_cost": fresh_plan["blast_cost"],
            "scenario_id": "cicd-compromise",
            "plan_fingerprint": fresh_plan["plan_fingerprint"],
        },
        headers=AUTH_HEADERS,
    )
    assert c_res.status_code == 200
    rec = c_res.json()
    assert rec["pre_paths"] == 2
    assert rec["post_paths"] == 0
    assert len(rec["sha256_receipt"]) == 64
    s_post = client.get("/api/state?source_id=ci-runner-07&scenario_id=cicd-compromise").json()
    assert s_post["active_path_count"] == 0

    # 7. Audit Log Record Verification
    audit_res = client.get("/api/audit")
    assert audit_res.status_code == 200
    audit_records = audit_res.json()
    assert len(audit_records) > 0
    latest_audit = audit_records[0]
    assert latest_audit["receipt_id"] == rec["receipt_id"]
    assert latest_audit["verified_zero_reachability"] is True

    print(f"[PASS] Feature 6 (Containment Commit): prod_graph paths 2->0 | SHA-256={rec['sha256_receipt'][:24]}...")
    print("=" * 78)
    print("ALL 6 LIVE FALKORDB FEATURES VERIFIED WITH ZERO SIMULATION.")
    print("=" * 78 + "\n")
