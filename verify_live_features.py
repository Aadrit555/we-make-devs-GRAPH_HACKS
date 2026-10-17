"""
TEZCATL — Live End-to-End Feature Verification Against FalkorDB
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def run_verification():
    print("\n" + "=" * 78)
    print("TEZCATL // LIVE 6-FEATURE FALKORDB VERIFICATION SUITE")
    print("=" * 78)

    # 1. Reset & Verify Topology
    r_reset = client.post("/api/reset")
    assert r_reset.status_code == 200
    s1 = client.get("/api/state?source_id=ci-runner-07").json()
    assert len(s1["topology"]["nodes"]) == 8, "Expected 8 :Entity nodes in FalkorDB"
    assert len(s1["topology"]["edges"]) == 8, "Expected 8 :ATTACK_STEP edges in FalkorDB"
    print(f"[PASS] Feature 1 (Live Topology): {len(s1['topology']['nodes'])} Entities, {len(s1['topology']['edges'])} Edges")

    # 2. Multi-Hop Path Discovery (*1..8)
    assert s1["active_path_count"] == 2, f"Expected 2 paths, got {s1['active_path_count']}"
    s_staging = client.get("/api/state?source_id=staging-worker-02").json()
    assert s_staging["active_path_count"] == 1, f"Expected 1 path for staging-worker-02, got {s_staging['active_path_count']}"
    print(f"[PASS] Feature 2 (Multi-Hop *1..8): ci-runner-07={s1['active_path_count']} paths | staging-worker-02={s_staging['active_path_count']} path")

    # 3. Centrality & Reverse :DEPENDS_ON Service Impact
    cand_map = {c["id"]: c for c in s1["candidates"]}
    assert cand_map["release-controller"]["blast_cost"] == 14
    assert cand_map["tok-deploy-alpha"]["blast_cost"] == 2
    assert cand_map["tok-artifact-rw"]["blast_cost"] == 3
    print(f"[PASS] Feature 3 (Service Impact): release-controller=14, tok-deploy-alpha=2, tok-artifact-rw=3")

    # 4. Minimum-Cut Solver & Shadow-Graph Sandbox (tezcatl_mirror)
    opt = s1["cut_solution"]["optimal"]
    assert set(opt["cut_nodes"]) == {"tok-deploy-alpha", "tok-artifact-rw"}
    assert opt["blast_cost"] == 5
    assert s1["mirror_proof"]["remaining_paths"] == 0
    assert s1["mirror_proof"]["verified_safe"] is True
    print(f"[PASS] Feature 4 (Shadow Mirror): Cut {opt['cut_nodes']} (Cost=5) -> 0 paths in tezcatl_mirror while prod_graph has 2")

    # 5. Live Bypass Edge Injection (EV-999)
    client.post("/api/mutate/bypass", json={"source_id": "ci-runner-07"})
    s_bypass = client.get("/api/state?source_id=ci-runner-07").json()
    assert s_bypass["active_path_count"] == 3, "Expected 3 paths after bypass injection"
    opt_bypass = s_bypass["cut_solution"]["optimal"]
    assert opt_bypass["cut_nodes"] == ["release-controller"]
    assert opt_bypass["blast_cost"] == 14
    assert s_bypass["mirror_proof"]["remaining_paths"] == 0
    print(f"[PASS] Feature 5 (Live Bypass EV-999): Paths jumped 2->3 | Solver shifted cut to {opt_bypass['cut_nodes']} (Cost=14)")

    # 6. Production Containment Commit & SHA-256 Receipt
    client.post("/api/reset")
    c_res = client.post(
        "/api/contain",
        json={"source_id": "ci-runner-07", "cut_nodes": ["tok-deploy-alpha", "tok-artifact-rw"], "blast_cost": 5},
    ).json()
    assert c_res["pre_paths"] == 2
    assert c_res["post_paths"] == 0
    assert len(c_res["sha256_receipt"]) == 64
    s_post = client.get("/api/state?source_id=ci-runner-07").json()
    assert s_post["active_path_count"] == 0
    print(f"[PASS] Feature 6 (Containment Commit): prod_graph paths 2->0 | SHA-256={c_res['sha256_receipt'][:24]}...")
    print("=" * 78)
    print("ALL 6 LIVE FALKORDB FEATURES VERIFIED WITH ZERO SIMULATION.")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    run_verification()
