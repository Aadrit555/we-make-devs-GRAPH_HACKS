"""
TEZCATL Live Feature Audit Script
Verifies all 6 core features against live FalkorDB instance and measures execution latencies.
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""

import time
import sys
from config import settings
from graph_client import FalkorGraphClient
import seed
import solver

def run_audit():
    print("=" * 70)
    print("TEZCATL // FALKORDB LIVE FEATURE AUDIT & LATENCY BENCHMARK")
    print(f"Target: {settings.falkordb_host}:{settings.falkordb_port}")
    print(f"Prod Graph: {settings.falkordb_graph} | Mirror Graph: {settings.falkordb_mirror_graph}")
    print("=" * 70)

    # Step 0: Ensure Pristine Seed
    t0 = time.perf_counter()
    seed.seed_database(settings.falkordb_host, settings.falkordb_port, settings.falkordb_graph)
    seed_ms = (time.perf_counter() - t0) * 1000
    print(f"[0] SEED DATABASE: OK in {seed_ms:.2f} ms")

    client = FalkorGraphClient(settings.falkordb_host, settings.falkordb_port, settings.falkordb_graph)

    # Feature 1: Multi-Hop Attack Path Discovery (*1..8)
    t1 = time.perf_counter()
    paths = client.discover_attack_paths("ci-runner-07", max_hops=8)
    f1_ms = (time.perf_counter() - t1) * 1000
    print(f"\n[1] FEATURE 1: MULTI-HOP ATTACK PATH DISCOVERY")
    print(f"    - Execution Latency: {f1_ms:.2f} ms")
    print(f"    - Active Paths Found: {len(paths)}")
    for i, p in enumerate(paths):
        print(f"      Route {i+1} ({p.hops} hops): {' -> '.join(p.node_ids)}")
    assert len(paths) == 2, f"Expected 2 paths, got {len(paths)}"

    # Feature 2: Native FalkorDB algo.betweenness Centrality
    t2 = time.perf_counter()
    centralities = client.get_betweenness_centrality()
    f2_ms = (time.perf_counter() - t2) * 1000
    print(f"\n[2] FEATURE 2: NATIVE FALKORDB ALGO.BETWEENNESS CENTRALITY")
    print(f"    - Execution Latency: {f2_ms:.2f} ms")
    print(f"    - Ranked Entities ({len(centralities)} total):")
    for c in centralities[:4]:
        print(f"      Node: {c.id:<25} Score: {c.score:<6.2f} (Kind: {c.kind})")
    assert centralities[0].id == "release-controller", f"Expected release-controller top bottleneck, got {centralities[0].id}"

    # Feature 3: Dynamic Service Blast Radius via Reverse DEPENDS_ON Traversal
    t3 = time.perf_counter()
    path_nodes = sorted(list({nid for p in paths for nid in p.node_ids}))
    candidates = client.get_cut_candidates(path_nodes, source_id="ci-runner-07")
    f3_ms = (time.perf_counter() - t3) * 1000
    print(f"\n[3] FEATURE 3: REVERSE DEPENDENCY SERVICE BLAST RADIUS")
    print(f"    - Execution Latency: {f3_ms:.2f} ms")
    print(f"    - Candidate Disruption Costs:")
    for cand in candidates:
        print(f"      Candidate: {cand.id:<22} Cost: {cand.cost:<3} Services: {cand.downstream_services}")

    # Feature 4: Deterministic Minimum-Cost Vertex-Cut Solver
    t4 = time.perf_counter()
    cand_costs = {c.id: c.cost for c in candidates}
    plan = solver.compute_minimum_cost_cut(
        attack_paths=[p.node_ids for p in paths],
        candidate_costs=cand_costs,
        source_id="ci-runner-07",
        crown_jewel_ids={"prod-signing-key"}
    )
    f4_ms = (time.perf_counter() - t4) * 1000
    print(f"\n[4] FEATURE 4: DETERMINISTIC MINIMUM-COST VERTEX-CUT SOLVER")
    print(f"    - Execution Latency: {f4_ms:.2f} ms")
    print(f"    - Optimal Cut: {plan.selected_node_ids}")
    print(f"    - Optimal Blast Cost: {plan.total_cost} (vs release-controller cost {cand_costs['release-controller']})")
    assert set(plan.selected_node_ids) == {"tok-deploy-alpha", "tok-artifact-rw"}
    assert plan.total_cost == 5

    # Feature 5: True Live Graph Cloning & Shadow Verification in tezcatl_mirror
    t5 = time.perf_counter()
    sim = client.verify_in_smoking_mirror(
        blocked_ids=plan.selected_node_ids,
        source_id="ci-runner-07",
        target_id="prod-signing-key",
        max_hops=8,
        mirror_graph_name=settings.falkordb_mirror_graph
    )
    f5_ms = (time.perf_counter() - t5) * 1000
    print(f"\n[5] FEATURE 5: LIVE SHADOW-GRAPH CLONING & VERIFICATION")
    print(f"    - Execution Latency: {f5_ms:.2f} ms")
    print(f"    - Target Graph: {sim['mirror_graph_name']}")
    print(f"    - Severed Entities in Sandbox: {sim['blocked_ids']}")
    print(f"    - Remaining Paths in Mirror: {sim['mirror_remaining_count']}")
    print(f"    - Production Untouched Paths: {client.count_remaining_paths('ci-runner-07')}")
    assert sim["verified_contained"] is True
    assert sim["mirror_remaining_count"] == 0
    assert client.count_remaining_paths("ci-runner-07") == 2

    # Feature 6: Bypass Edge Stress-Test (Dynamic Graph Mutation)
    t6 = time.perf_counter()
    client.inject_bypass_edge("ci-runner-07", "release-controller", "EV-STRESS-LIVE")
    paths_with_bypass = client.discover_attack_paths("ci-runner-07")
    cands_bypass = client.get_cut_candidates(
        sorted(list({nid for p in paths_with_bypass for nid in p.node_ids})),
        source_id="ci-runner-07"
    )
    plan_bypass = solver.compute_minimum_cost_cut(
        attack_paths=[p.node_ids for p in paths_with_bypass],
        candidate_costs={c.id: c.cost for c in cands_bypass},
        source_id="ci-runner-07",
        crown_jewel_ids={"prod-signing-key"}
    )
    # Cleanup bypass
    client.remove_bypass_edge("EV-STRESS-LIVE")
    paths_after_cleanup = client.discover_attack_paths("ci-runner-07")
    f6_ms = (time.perf_counter() - t6) * 1000
    print(f"\n[6] FEATURE 6: BYPASS EDGE INJECTION & DYNAMIC RE-SOLVING")
    print(f"    - Execution Latency: {f6_ms:.2f} ms")
    print(f"    - Paths with Direct Bypass: {len(paths_with_bypass)}")
    print(f"    - Dynamically Shifted Optimal Cut: {plan_bypass.selected_node_ids} (Cost: {plan_bypass.total_cost})")
    print(f"    - Paths after Bypass Teardown: {len(paths_after_cleanup)}")
    assert len(paths_with_bypass) == 3
    assert plan_bypass.selected_node_ids == ["release-controller"]
    assert len(paths_after_cleanup) == 2

    print("\n" + "=" * 70)
    print("ALL 6 LIVE FALKORDB FEATURES VERIFIED WITH ZERO SIMULATION!")
    print(f"Total Audit Pipeline Time: {seed_ms + f1_ms + f2_ms + f3_ms + f4_ms + f5_ms + f6_ms:.2f} ms")
    print("=" * 70)

if __name__ == "__main__":
    run_audit()
