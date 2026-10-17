"""
TEZCATL — Isolated Test Architecture & Multi-Scenario Test Suite
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)

Executes Scenarios A, B, C, D exclusively against isolated test graphs
(tezcatl_test_prod & tezcatl_test_mirror) without modifying or resetting prod_graph.
"""
import pytest
import math
from falkordb import FalkorDB
from backend.config import FALKORDB_HOST, FALKORDB_PORT
from backend.graph_client import TezcatlGraphEngine
from backend.seed import ENTITY_NODES, SERVICE_NODES, ATTACK_STEPS, DEPENDENCIES

TEST_PROD_GRAPH = "tezcatl_test_prod"
TEST_MIRROR_GRAPH = "tezcatl_test_mirror"


@pytest.fixture(scope="module")
def test_engine():
    """Initializes a dedicated graph engine bound strictly to isolated test graphs."""
    engine = TezcatlGraphEngine(
        host=FALKORDB_HOST,
        port=FALKORDB_PORT,
        prod_name=TEST_PROD_GRAPH,
        mirror_name=TEST_MIRROR_GRAPH,
    )
    # Seed isolated test prod graph
    engine.seed_topology(TEST_PROD_GRAPH)
    engine.clone_prod_to_mirror()
    return engine


def test_scenario_a_baseline_topology(test_engine):
    """Scenario A: Standard baseline architecture with 8 nodes, 2 active paths, optimal cut cost 5."""
    # 1. Reset test graph
    test_engine.seed_topology(TEST_PROD_GRAPH)
    test_engine.clone_prod_to_mirror()

    # 2. Topology inspection
    topo, tel = test_engine.get_full_topology(TEST_PROD_GRAPH)
    assert len(topo["nodes"]) == 8, f"Expected 8 entities, got {len(topo['nodes'])}"
    assert len(topo["edges"]) == 8, f"Expected 8 attack edges, got {len(topo['edges'])}"

    # 3. Multi-Hop Path Discovery (*1..8)
    paths, _ = test_engine.find_attack_paths("ci-runner-07", graph_name=TEST_PROD_GRAPH)
    assert len(paths) == 2, f"Expected 2 paths from ci-runner-07, got {len(paths)}"

    # 4. Centrality & Reverse Blast Radius
    candidates, _ = test_engine.compute_centrality_and_blast_radius(paths, graph_name=TEST_PROD_GRAPH)
    cand_map = {c["id"]: c for c in candidates}
    assert cand_map["release-controller"]["blast_cost"] == 14
    assert cand_map["tok-deploy-alpha"]["blast_cost"] == 2
    assert cand_map["tok-artifact-rw"]["blast_cost"] == 3

    # 5. Solver Minimum-Cut & Shadow-Graph Verification
    cut_sol = test_engine.solve_minimum_cut_set("ci-runner-07", paths, candidates)
    opt = cut_sol["optimal"]
    assert set(opt["cut_nodes"]) == {"tok-deploy-alpha", "tok-artifact-rw"}
    assert opt["blast_cost"] == 5

    # 6. Verify in isolated mirror
    proof = test_engine.verify_in_shadow_mirror("ci-runner-07", opt["cut_nodes"])
    assert proof["remaining_paths"] == 0
    assert proof["verified_safe"] is True


def test_scenario_b_bypass_architecture(test_engine):
    """Scenario B: Alternative bypass edge EV-999 dynamically shifting optimal cut to release-controller."""
    # 1. Inject bypass into isolated test graph
    res = test_engine.inject_bypass_edge("ci-runner-07")
    assert res["status"] == "bypass_injected"

    # 2. Re-discover paths
    paths, _ = test_engine.find_attack_paths("ci-runner-07", graph_name=TEST_PROD_GRAPH)
    assert len(paths) == 3, f"Expected 3 paths after bypass injection, got {len(paths)}"

    # 3. Re-compute centrality and blast radius
    candidates, _ = test_engine.compute_centrality_and_blast_radius(paths, graph_name=TEST_PROD_GRAPH)

    # 4. Re-solve optimal cut
    cut_sol = test_engine.solve_minimum_cut_set("ci-runner-07", paths, candidates)
    opt = cut_sol["optimal"]
    assert opt["cut_nodes"] == ["release-controller"], f"Expected cut shift to release-controller, got {opt['cut_nodes']}"
    assert opt["blast_cost"] == 14

    # 5. Shadow-graph sandbox verification
    proof = test_engine.verify_in_shadow_mirror("ci-runner-07", opt["cut_nodes"])
    assert proof["remaining_paths"] == 0
    assert proof["verified_safe"] is True


def test_scenario_c_contained_topology(test_engine):
    """Scenario C: Apply containment to isolated test graph, verify 0 reachability and SHA-256 receipt."""
    # Reset test graph to baseline
    test_engine.seed_topology(TEST_PROD_GRAPH)
    test_engine.clone_prod_to_mirror()

    pre_paths, _ = test_engine.find_attack_paths("ci-runner-07", graph_name=TEST_PROD_GRAPH)
    assert len(pre_paths) == 2

    # Commit containment for optimal cut set
    receipt = test_engine.commit_containment("ci-runner-07", ["tok-deploy-alpha", "tok-artifact-rw"], blast_cost=5)
    assert receipt["pre_paths"] == 2
    assert receipt["post_paths"] == 0
    assert len(receipt["sha256_receipt"]) == 64

    # Re-query test graph: reachability is zero
    post_paths, _ = test_engine.find_attack_paths("ci-runner-07", graph_name=TEST_PROD_GRAPH)
    assert len(post_paths) == 0


def test_scenario_d_new_nodes_and_branches(test_engine):
    """Scenario D: Test-only topology with 2 additional entities and 1 alternative attack route."""
    # Connect directly to FalkorDB for custom test topology
    db = test_engine.db
    g = db.select_graph(TEST_PROD_GRAPH)
    g.query("MATCH (n) DETACH DELETE n")

    # Seed baseline entities + 2 new entities
    extra_entities = [
        *ENTITY_NODES,
        {"id": "ci-cache-proxy", "name": "CI Cache Proxy Node", "kind": "workload", "criticality": "high", "status": "active"},
        {"id": "tok-cache-admin", "name": "Cache Admin Token", "kind": "credential", "criticality": "high", "status": "active"},
    ]
    for ent in extra_entities:
        g.query(
            "CREATE (:Entity {id: $id, name: $name, kind: $kind, criticality: $criticality, status: $status})",
            params=ent,
        )

    for svc in SERVICE_NODES:
        g.query("CREATE (:Service {id: $id, name: $name, revenue_weight: $weight})", params=svc)

    # Seed baseline attack steps + new alternative route
    extra_steps = [
        *ATTACK_STEPS,
        {"src": "ci-runner-07", "dst": "ci-cache-proxy", "mech": "PROXY_TUNNEL", "ev": "EV-201"},
        {"src": "ci-cache-proxy", "dst": "tok-cache-admin", "mech": "TOKEN_INSPECT", "ev": "EV-202"},
        {"src": "tok-cache-admin", "dst": "release-controller", "mech": "ADMIN_OVERRIDE", "ev": "EV-203"},
    ]
    for step in extra_steps:
        g.query(
            "MATCH (a:Entity {id: $src}), (b:Entity {id: $dst}) CREATE (a)-[:ATTACK_STEP {mechanism: $mech, evidence_id: $ev, active: true}]->(b)",
            params=step,
        )

    for dep in DEPENDENCIES:
        g.query("MATCH (s:Service {id: $svc}), (e:Entity {id: $ent}) CREATE (s)-[:DEPENDS_ON]->(e)", params=dep)

    # 1. Verify Topology has 10 entities and 11 attack edges
    topo, _ = test_engine.get_full_topology(TEST_PROD_GRAPH)
    assert len(topo["nodes"]) == 10, f"Expected 10 entities, got {len(topo['nodes'])}"
    assert len(topo["edges"]) == 11, f"Expected 11 attack edges, got {len(topo['edges'])}"

    # 2. Verify 3 active attack paths
    paths, _ = test_engine.find_attack_paths("ci-runner-07", graph_name=TEST_PROD_GRAPH)
    assert len(paths) == 3, f"Expected 3 attack paths in Scenario D, got {len(paths)}"

    # 3. Verify Deterministic Layout Math for 10 nodes (zero overlapping coordinates)
    # Simulate the JavaScript layout logic in Python to verify coordinate separation
    coords = simulate_layout(topo["nodes"], topo["edges"], paths, "ci-runner-07")
    assert len(coords) == 10

    # Ensure all 10 nodes have non-overlapping coordinates (min distance > 40px)
    node_ids = list(coords.keys())
    for i in range(len(node_ids)):
        for j in range(i + 1, len(node_ids)):
            n1 = node_ids[i]
            n2 = node_ids[j]
            c1 = coords[n1]
            c2 = coords[n2]
            dist = math.hypot(c1["x"] - c2["x"], c1["y"] - c2["y"])
            assert dist >= 45, f"Collision detected between {n1} ({c1}) and {n2} ({c2}): distance {dist:.1f}px"

    # Source must be in leftmost layer, crown jewel in rightmost layer
    assert coords["ci-runner-07"]["x"] <= 100
    assert coords["prod-signing-key"]["x"] >= 650


def simulate_layout(nodes, edges, paths, source_id):
    """Python verification replica of computeDynamicLayout to mathematically prove zero overlap."""
    crown_set = {n["id"] for n in nodes if n.get("criticality") == "crown_jewel"}
    adj = {n["id"]: [] for n in nodes}
    rev_adj = {n["id"]: [] for n in nodes}
    for e in edges:
        if e["source"] in adj:
            adj[e["source"]].append(e["target"])
        if e["target"] in rev_adj:
            rev_adj[e["target"]].append(e["source"])

    ingress = {source_id}
    for n in nodes:
        if len(rev_adj[n["id"]]) == 0 and n["id"] not in crown_set:
            ingress.add(n["id"])

    layer = {src: 0 for src in ingress}
    queue = list(ingress)
    visits = {id: 1 for id in ingress}

    while queue:
        curr = queue.pop(0)
        curr_l = layer.get(curr, 0)
        for nxt in adj.get(curr, []):
            if nxt in crown_set:
                continue
            prev_l = layer.get(nxt, -1)
            next_l = max(prev_l, curr_l + 1)
            count = visits.get(nxt, 0)
            if count < 8 and next_l < 12:
                layer[nxt] = next_l
                visits[nxt] = count + 1
                queue.append(nxt)

    for n in nodes:
        if n["id"] not in layer and n["id"] not in crown_set:
            layer[n["id"]] = 1

    max_inter = max([layer[n["id"]] for n in nodes if n["id"] not in crown_set], default=0)
    crown_layer = max_inter + 1
    for cid in crown_set:
        layer[cid] = crown_layer

    total_layers = max(crown_layer + 1, 2)
    layer_groups = [[] for _ in range(total_layers)]
    for n in nodes:
        l = min(layer.get(n["id"], 0), totalLayers - 1 if "totalLayers" in dir() else total_layers - 1)
        layer_groups[l].append(n)

    svg_width = 780
    svg_height = 270
    x_margin = 80
    x_step = (svg_width - 2 * x_margin) / (total_layers - 1) if total_layers > 1 else 0

    coords = {}
    for l, group in enumerate(layer_groups):
        x = round(x_margin + (l * x_step))
        k = len(group)
        y_center = svg_height / 2
        for idx, node in enumerate(group):
            if k == 1:
                y = y_center
            elif k == 2:
                y = y_center - 58 if idx == 0 else y_center + 58
            else:
                y_top = 46
                y_bottom = svg_height - 46
                y_step = (y_bottom - y_top) / (k - 1)
                y = round(y_top + (idx * y_step))
            coords[node["id"]] = {"x": x, "y": y, "layer": l}
    return coords
