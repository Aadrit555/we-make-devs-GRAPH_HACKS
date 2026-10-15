"""
TEZCATL Sovereign Graph Engine — Authored by Aadrit555
tests/test_tezcatl.py — Comprehensive Test Suite for Track 01 Submission.

Exhaustively verifies:
1. Seed topology, schema properties, and cold-start auto-bootstrapping
2. Bounded multi-hop traversal (*1..8) and evidence ID integrity
3. Native FalkorDB betweenness centrality (algo.betweenness)
4. Dynamic operational blast-radius calculation via reverse DEPENDS_ON traversal
5. Combinatorial minimum-cost vertex-cut solver with operator protection
6. First-party JSON-RPC 2.0 Model Context Protocol (MCP) tool server
7. Smoking Mirror multi-graph sandbox isolation (tezcatl_mirror vs. prod_graph)
8. Sovereign Track 01 agent orchestration (TezcatlAgent)
9. Human-in-the-loop containment commit, post-action zero-path verification, and audit receipts
10. Parameterized Cypher verification (zero string formatting / f-strings in queries)
"""

import pytest
import re
import json
import seed
from config import settings
from graph_client import (
    FalkorGraphClient,
    ReadOnlyGraphClient,
    validate_node_id,
    DatabaseConnectionError,
    GraphQueryError,
)
import solver
from mcp_server import McpServer
from agent import TezcatlAgent
from models import (
    AttackPath,
    CentralityScore,
    MitigationCandidate,
    CutPlan,
    ContainmentAuditReceipt,
    GraphFreshnessError,
)

FALKORDB_HOST = settings.falkordb_host
FALKORDB_PORT = settings.falkordb_port
PROD_GRAPH = settings.falkordb_graph
MIRROR_GRAPH = settings.falkordb_mirror_graph


@pytest.fixture(scope="module", autouse=True)
def pristine_database():
    """Ensure clean pristine seeded topology before testing."""
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=PROD_GRAPH)


@pytest.fixture
def client():
    return FalkorGraphClient(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=PROD_GRAPH)


@pytest.fixture
def mcp(client):
    return McpServer(client=client)


@pytest.fixture
def agent(client, mcp):
    return TezcatlAgent(client=client, mcp=mcp, mirror_graph_name=MIRROR_GRAPH)


# ==============================================================================
# 1. Parameterization Check: Zero String Interpolation in Cypher Queries
# ==============================================================================

def test_query_parameterization_invariance():
    """Confirm zero f-strings or raw string formatting in graph_client Cypher queries."""
    import graph_client
    for attr_name in dir(graph_client):
        if attr_name.startswith("QUERY_"):
            query_val = getattr(graph_client, attr_name)
            assert isinstance(query_val, str)
            # Verify parameters use $ prefix and no curly-brace f-string placeholders like {variable}
            # Note: JSON-like syntax inside algo.betweenness({nodeLabels: ...}) is permitted
            assert not re.search(r"\{\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\}", query_val), (
                f"Query {attr_name} contains unparameterized string placeholder!"
            )


# ==============================================================================
# 2. Database Connectivity & Cold-Start Auto-Bootstrap
# ==============================================================================

def test_falkordb_ping_and_connection(client):
    assert client.check_connection(auto_bootstrap=False) is True


def test_seed_database_counts(client):
    """Verify exact baseline topology: 25 entities (9 services), 10 attack steps, 19 dependencies."""
    res_nodes = client.graph.query("MATCH (n:Entity) RETURN count(n) AS cnt")
    res_services = client.graph.query("MATCH (s:Service) RETURN count(s) AS cnt")
    res_attacks = client.graph.query("MATCH ()-[r:ATTACK_STEP]->() RETURN count(r) AS cnt")
    res_deps = client.graph.query("MATCH ()-[r:DEPENDS_ON]->() RETURN count(r) AS cnt")

    assert res_nodes.result_set[0][0] == 25
    assert res_services.result_set[0][0] == 9
    assert res_attacks.result_set[0][0] == 10
    assert res_deps.result_set[0][0] == 19


def test_auto_bootstrap_on_empty_graph():
    """Verify that check_connection with auto_bootstrap=True populates an empty graph."""
    empty_test_graph = "tezcatl_autobootstrap_test"
    db_client = FalkorGraphClient(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=empty_test_graph)
    # Clear graph if it exists
    try:
        db_client.graph.query("MATCH (n) DETACH DELETE n")
    except Exception:
        pass

    # check_connection with auto_bootstrap must detect 0 entities and run seed_database
    connected = db_client.check_connection(auto_bootstrap=True)
    assert connected is True

    # Verify entities exist now
    cnt_res = db_client.graph.query("MATCH (n:Entity) RETURN count(n) AS cnt")
    assert cnt_res.result_set[0][0] == 25

    # Clean up test graph
    db_client.graph.query("MATCH (n) DETACH DELETE n")


# ==============================================================================
# 3. Multi-Hop Attack Traversal & Native Centrality
# ==============================================================================

def test_path_discovery_bounded_to_8_hops(client):
    paths = client.discover_attack_paths(source_id="ci_runner", target_id="signing_key", max_hops=8)
    assert len(paths) == 3
    for p in paths:
        assert p.hops <= 8
        assert p.node_ids[0] == "ci_runner"
        assert p.node_ids[-1] == "signing_key"


def test_evidence_id_integrity(client):
    paths = client.discover_attack_paths(source_id="ci_runner", target_id="signing_key", max_hops=8)
    all_evidence = [ev for p in paths for ev in p.evidence_ids]
    assert "E-001" in all_evidence
    assert "E-004" in all_evidence
    assert "E-010" in all_evidence


def test_native_falkordb_betweenness_centrality(client):
    scores = client.get_betweenness_centrality()
    assert len(scores) > 0
    # release_controller is the structural bottleneck bridging all paths to signer_role
    top = scores[0]
    assert top.id == "release_controller"
    assert top.score == 12.0


# ==============================================================================
# 4. Dynamic Blast Radius Calculus via Reverse DEPENDS_ON Traversal
# ==============================================================================

def test_graph_computed_blast_radius(client):
    paths = client.discover_attack_paths(source_id="ci_runner", target_id="signing_key")
    all_path_nodes = list(dict.fromkeys([nid for p in paths for nid in p.node_ids]))
    candidates = client.get_cut_candidates(path_node_ids=all_path_nodes, source_id="ci_runner")

    cost_map = {c.id: c.cost for c in candidates}
    assert cost_map["deploy_token"] == 2
    assert cost_map["artifact_token"] == 3
    assert cost_map["release_controller"] == 10

    # Verify release_controller dependencies include Checkout API (score 5) and Billing Worker (score 3)
    controller = next(c for c in candidates if c.id == "release_controller")
    assert "Checkout API" in controller.downstream_services
    assert "Billing Worker" in controller.downstream_services


# ==============================================================================
# 5. Combinatorial Minimum-Cost Vertex-Cut Solver
# ==============================================================================

def test_combinatorial_solver_optimal_cut(client):
    paths = client.discover_attack_paths(source_id="ci_runner")
    path_nodes = [p.node_ids for p in paths]
    candidate_costs = {"deploy_token": 2, "artifact_token": 3, "release_controller": 10}

    plan = solver.compute_minimum_cost_cut(
        attack_paths=path_nodes,
        candidate_costs=candidate_costs,
        source_id="ci_runner",
        crown_jewel_ids={"signing_key"},
    )

    assert plan.total_cost == 5
    assert set(plan.selected_node_ids) == {"deploy_token", "artifact_token"}
    assert plan.paths_covered_count == 3


def test_suboptimal_release_controller_rejected(client):
    paths = client.discover_attack_paths(source_id="ci_runner")
    path_nodes = [p.node_ids for p in paths]
    candidate_costs = {"deploy_token": 2, "artifact_token": 3, "release_controller": 10}

    # Severing release_controller severs all paths, but costs 10 vs 5
    assert client.count_remaining_paths(source_id="ci_runner", severed_ids=["release_controller"]) == 0
    # Single tokens do NOT sever all paths
    assert client.count_remaining_paths(source_id="ci_runner", severed_ids=["deploy_token"]) > 0
    assert client.count_remaining_paths(source_id="ci_runner", severed_ids=["artifact_token"]) > 0


def test_solver_operator_protection_constraint(client):
    paths = client.discover_attack_paths(source_id="ci_runner")
    path_nodes = [p.node_ids for p in paths]
    candidate_costs = {
        "deploy_token": 2,
        "artifact_token": 3,
        "legacy_release_session": 4,
        "production_deploy_role": 6,
        "artifact_registry": 7,
        "signer_role": 8,
        "release_controller": 10,
    }

    # Pin deploy_token as protected from cut
    plan = solver.compute_minimum_cost_cut(
        attack_paths=path_nodes,
        candidate_costs=candidate_costs,
        source_id="ci_runner",
        crown_jewel_ids={"signing_key"},
        exclude_ids=["deploy_token"],
    )

    assert "deploy_token" not in plan.selected_node_ids
    assert plan.paths_covered_count == 3


# ==============================================================================
# 6. JSON-RPC 2.0 Model Context Protocol (MCP) Server
# ==============================================================================

def test_mcp_tools_list(mcp):
    response = mcp.handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
    })
    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 1
    tools = response["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "scry_attack_paths" in tool_names
    assert "rank_betweenness_bottlenecks" in tool_names
    assert "compute_service_blast_radius" in tool_names
    assert "simulate_mirror_containment" in tool_names
    assert "apply_containment_action" in tool_names


def test_mcp_tools_call_scry_paths(mcp):
    response = mcp.handle_request({
        "jsonrpc": "2.0",
        "id": "req-2",
        "method": "tools/call",
        "params": {
            "name": "scry_attack_paths",
            "arguments": {"source_id": "ci_runner", "max_hops": 8},
        },
    })
    assert response["jsonrpc"] == "2.0"
    assert response["id"] == "req-2"
    paths = response["result"]["content"]
    assert len(paths) == 3


def test_mcp_tools_call_mirror_simulation(mcp):
    response = mcp.handle_request({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "simulate_mirror_containment",
            "arguments": {
                "blocked_ids": ["deploy_token", "artifact_token"],
                "source_id": "ci_runner",
                "mirror_graph_name": MIRROR_GRAPH,
            },
        },
    })
    assert response["jsonrpc"] == "2.0"
    sim_result = response["result"]["content"]
    assert sim_result["verified_contained"] is True
    assert sim_result["mirror_remaining_count"] == 0


def test_mcp_unknown_method_error(mcp):
    response = mcp.handle_request({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "non_existent_tool",
    })
    assert response["error"]["code"] == -32601


# ==============================================================================
# 7. Smoking Mirror Multi-Graph Sandbox Isolation
# ==============================================================================

def test_shadow_mirror_sandbox_isolation(client):
    """Verify that mutations in tezcatl_mirror do NOT affect prod_graph."""
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=PROD_GRAPH)

    # Clone to mirror and mutate mirror
    mirror_client = client.clone_to_mirror(mirror_graph_name=MIRROR_GRAPH)
    mirror_client.apply_containment_action(["deploy_token", "artifact_token"])

    # Mirror has 0 remaining paths
    assert mirror_client.count_remaining_paths("ci_runner") == 0

    # Production STILL HAS 3 active paths (unmutated!)
    assert client.count_remaining_paths("ci_runner") == 3


# ==============================================================================
# 8. Sovereign Track 01 Autonomous Agent (TezcatlAgent)
# ==============================================================================

def test_tezcatl_agent_investigation_e2e(agent):
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=PROD_GRAPH)

    analysis, stages = agent.run_investigation(
        raw_query="Contain breach from ci_runner to signing_key within 8 hops protect release_controller",
        run_mirror_sim=True,
    )

    assert len(stages) == 5
    assert len(analysis.discovered_paths) == 3
    assert analysis.recommended_plan is not None
    assert analysis.recommended_plan.total_cost == 5
    assert set(analysis.recommended_plan.selected_node_ids) == {"deploy_token", "artifact_token"}
    assert analysis.counterfactual_remaining_paths == 0
    assert analysis.audit_receipt is not None
    assert analysis.audit_receipt.verification_status == "CONTAINED_AND_VERIFIED"


def test_tezcatl_agent_containment_commit_and_verification(agent, client):
    """Test gated human execution: commit verified cut to production and verify 0 paths."""
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=PROD_GRAPH)

    mut_res, receipt = agent.execute_containment(
        source_id="ci_runner",
        target_id="signing_key",
        expected_cut_ids=["deploy_token", "artifact_token"],
        incident_id="INC-FINAL-TEST",
    )

    assert len(mut_res.disabled_ids) == 2
    assert receipt.verified_remaining_paths == 0
    assert receipt.verification_status == "CONTAINED_AND_VERIFIED"
    assert receipt.pre_mitigation_graph_hash != receipt.post_mitigation_graph_hash

    # Fresh query confirms production reachability is zero
    assert agent.verify_containment_post_action("ci_runner", "signing_key") == 0

    # Re-executing containment on already-contained graph raises GraphFreshnessError
    with pytest.raises(GraphFreshnessError):
        agent.execute_containment(
            source_id="ci_runner",
            target_id="signing_key",
            expected_cut_ids=["deploy_token", "artifact_token"],
        )

    # Restore pristine seed graph for subsequent checks
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=PROD_GRAPH)


# ==============================================================================
# 9. Cryptographic Audit Receipt & Security Invariants
# ==============================================================================

def test_cryptographic_receipt_json_and_markdown(agent):
    analysis, _ = agent.run_investigation()
    receipt = analysis.audit_receipt
    assert receipt is not None

    json_str = receipt.to_json()
    assert '"incident_id"' in json_str
    assert '"pre_mitigation_graph_hash"' in json_str

    md_str = receipt.to_markdown()
    assert "# TEZCATL Containment Audit Receipt" in md_str
    assert "CONTAINED_AND_VERIFIED" in md_str


def test_strict_node_id_validation():
    with pytest.raises(ValueError):
        validate_node_id("bad id with spaces")
    with pytest.raises(ValueError):
        validate_node_id("'; DROP GRAPH prod_graph; --")
    assert validate_node_id("valid_node-123") == "valid_node-123"


def test_read_only_client_lockdown(client):
    ro_client = ReadOnlyGraphClient(client)
    with pytest.raises(PermissionError):
        ro_client.apply_containment_action(["deploy_token"])
    with pytest.raises(PermissionError):
        ro_client.update_node_cost("deploy_token", 5)


# ==============================================================================
# 10. Stress-Testing, Schema, and Combinatorial Edge Cases
# ==============================================================================

def test_judge_stress_testing_and_bypass_route(client):
    """Stress test: inject bypass edge, observe 4 paths, then remove and observe return to 3."""
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=PROD_GRAPH)

    # Inject bypass edge from ci_runner directly to release_controller
    client.inject_bypass_edge(
        source_id="ci_runner",
        target_id="release_controller",
        evidence_id="E-STRESS-BYPASS"
    )

    paths_after_inject = client.discover_attack_paths(source_id="ci_runner")
    assert len(paths_after_inject) == 4

    # Remove bypass edge
    client.remove_bypass_edge("E-STRESS-BYPASS")
    paths_after_remove = client.discover_attack_paths(source_id="ci_runner")
    assert len(paths_after_remove) == 3


def test_dynamic_cost_mutation_and_optimizer_reaction(client):
    """Update node cost in FalkorDB and verify solver reacts dynamically."""
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=PROD_GRAPH)

    # If release_controller cost drops to 3 (lower than deploy_token 2 + artifact_token 3 = 5),
    # solver must now select release_controller
    paths = client.discover_attack_paths(source_id="ci_runner")
    path_nodes = [p.node_ids for p in paths]
    dynamic_costs = {"deploy_token": 2, "artifact_token": 3, "release_controller": 3}

    plan = solver.compute_minimum_cost_cut(
        attack_paths=path_nodes,
        candidate_costs=dynamic_costs,
        source_id="ci_runner",
        crown_jewel_ids={"signing_key"}
    )

    assert plan.total_cost == 3
    assert plan.selected_node_ids == ["release_controller"]


def test_solver_error_conditions():
    """Verify solver raises typed errors on invalid inputs."""
    # Negative cost
    with pytest.raises(solver.InvalidCandidateDataError):
        solver.compute_minimum_cost_cut(
            attack_paths=[["a", "b"]],
            candidate_costs={"b": -1}
        )

    # Malformed path
    with pytest.raises(solver.InvalidCandidateDataError):
        solver.compute_minimum_cost_cut(
            attack_paths=[["single_node"]],
            candidate_costs={"single_node": 1}
        )

    # Empty paths returns zero plan
    zero_plan = solver.compute_minimum_cost_cut(
        attack_paths=[],
        candidate_costs={"a": 1}
    )
    assert zero_plan.total_cost == 0
    assert zero_plan.selected_node_ids == []

    # Infeasible candidate set raises NoValidCutError
    with pytest.raises(solver.NoValidCutError):
        solver.compute_minimum_cost_cut(
            attack_paths=[["src", "a", "dst"]],
            candidate_costs={"b": 1},
            source_id="src",
            crown_jewel_ids={"dst"}
        )


def test_entity_and_relationship_properties(client):
    """Verify entity labels and relationship properties."""
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=PROD_GRAPH)

    # Check signing_key is crown_jewel
    res = client.graph.query("MATCH (k:Entity {id: 'signing_key'}) RETURN k.criticality AS crit, k.kind AS kind")
    assert res.result_set[0][0] == "crown_jewel"
    assert res.result_set[0][1] == "key"

    # Check attack step has active and evidence_id
    res_edge = client.graph.query("MATCH ()-[r:ATTACK_STEP]->() RETURN r.active, r.evidence_id LIMIT 1")
    assert res_edge.result_set[0][0] is True
    assert res_edge.result_set[0][1].startswith("E-")


def test_live_query_telemetry_capture(client):
    """Confirm live telemetry captures roundtrip latency and internal runtime."""
    client.discover_attack_paths(source_id="ci_runner")
    telemetry = client.last_telemetry
    assert telemetry is not None
    assert telemetry.latency_ms >= 0.0
    assert telemetry.client_latency_ms >= 0.0
    assert len(telemetry.query) > 0


# ==============================================================================
# FastAPI Production Gateway Integration Tests
# ==============================================================================

from fastapi.testclient import TestClient
from app import app


@pytest.fixture
def http_client():
    return TestClient(app)


def test_fastapi_index_html_serving(http_client):
    """Verify exact Driftbar Meadow Footer index.html is served on GET /."""
    res = http_client.get("/")
    assert res.status_code == 200
    assert "Driftbar" in res.text
    assert "#f1f1ee" in res.text


def test_fastapi_health_endpoint(http_client):
    """Verify /api/health returns live FalkorDB connectivity."""
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=PROD_GRAPH)
    res = http_client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HEALTHY"
    assert data["node_count"] >= 25
    assert data["edge_count"] >= 29


def test_fastapi_investigate_endpoint(http_client):
    """Verify /api/investigate executes 5-stage pipeline and returns optimal cut."""
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=PROD_GRAPH)
    payload = {
        "source_id": "ci_runner",
        "target_id": "signing_key",
        "max_hops": 8,
        "exclude_ids": [],
    }
    res = http_client.post("/api/investigate", json=payload)
    assert res.status_code == 200
    data = res.json()
    analysis = data["analysis"]
    assert len(analysis["discovered_paths"]) == 3
    assert analysis["recommended_plan"]["total_cost"] == 5
    assert set(analysis["recommended_plan"]["selected_node_ids"]) == {"deploy_token", "artifact_token"}
    assert analysis["counterfactual_remaining_paths"] == 0
    assert "audit_receipt" in analysis


def test_fastapi_contain_endpoint(http_client):
    """Verify /api/contain commits containment, severs attack paths, and issues receipt."""
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=PROD_GRAPH)
    payload = {
        "source_id": "ci_runner",
        "target_id": "signing_key",
        "cut_node_ids": ["deploy_token", "artifact_token"],
        "incident_id": "INC-TEST-API",
        "max_hops": 8,
    }
    res = http_client.post("/api/contain", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "CONTAINED_AND_VERIFIED"
    assert data["receipt"]["verified_remaining_paths"] == 0
    assert data["receipt"]["pre_mitigation_graph_hash"] != data["receipt"]["post_mitigation_graph_hash"]


def test_fastapi_reset_endpoint(http_client):
    """Verify /api/reset restores pristine topology."""
    res = http_client.post("/api/reset")
    assert res.status_code == 200
    assert res.json()["status"] == "SUCCESS"


def test_fastapi_stress_endpoints(http_client):
    """Verify cost mutation and bypass edge injection endpoints."""
    # Cost mutation
    res = http_client.post("/api/stress/cost", json={"node_id": "deploy_token", "new_cost": 25})
    assert res.status_code == 200
    assert res.json()["new_cost"] == 25

    # Bypass injection and removal
    res_inject = http_client.post("/api/stress/bypass", json={"action": "inject"})
    assert res_inject.status_code == 200
    assert res_inject.json()["action"] == "injected"

    res_remove = http_client.post("/api/stress/bypass", json={"action": "remove"})
    assert res_remove.status_code == 200
    assert res_remove.json()["action"] == "removed"

    # Reset back to pristine
    http_client.post("/api/reset")


def test_fastapi_mcp_endpoint(http_client):
    """Verify /api/mcp handles standard JSON-RPC 2.0 requests."""
    # tools/list
    rpc_list = {
        "jsonrpc": "2.0",
        "id": "1",
        "method": "tools/list",
        "params": {},
    }
    res = http_client.post("/api/mcp", json=rpc_list)
    assert res.status_code == 200
    data = res.json()
    assert "result" in data
    tool_names = [t["name"] for t in data["result"]["tools"]]
    assert "scry_attack_paths" in tool_names
    assert "simulate_mirror_containment" in tool_names

    # tools/call
    rpc_call = {
        "jsonrpc": "2.0",
        "id": "2",
        "method": "tools/call",
        "params": {
            "name": "scry_attack_paths",
            "arguments": {"source_id": "ci_runner", "target_id": "signing_key", "max_hops": 8},
        },
    }
    res_call = http_client.post("/api/mcp", json=rpc_call)
    assert res_call.status_code == 200
    data_call = res_call.json()
    assert "result" in data_call
    assert len(data_call["result"]["content"]) == 3
