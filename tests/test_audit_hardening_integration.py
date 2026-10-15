"""
tests/test_audit_hardening_integration.py — Integration tests verifying Security Hardening,
Anti-Vibecode Refactor, Telemetry Instrumentation, Read/Write Segregation,
and TEZCATL Pure-Graph Upgrades.
"""

import pytest
import os
from graph_client import (
    FalkorGraphClient,
    ReadOnlyGraphClient,
    validate_node_id,
    DatabaseConnectionError,
    GraphQueryError,
)
from logic import ContainmentService
import seed
from config import settings

FALKORDB_HOST = settings.falkordb_host
FALKORDB_PORT = settings.falkordb_port
GRAPH_NAME = settings.falkordb_graph


@pytest.fixture(autouse=True)
def reset_clean_seed():
    """Ensure pristine graph seed before each test."""
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)


def test_strict_node_id_regex_validation():
    """Validates that illegal or malicious node IDs are rejected before touching Cypher."""
    valid_ids = ["ci_runner", "signing-key-01", "Node123", "a"]
    for vid in valid_ids:
        assert validate_node_id(vid) == vid

    invalid_ids = [
        "'; DROP ALL; //",
        "ci runner",
        "node$name",
        "node#1",
        "a" * 65,  # Exceeds 64 chars
        "",
        "node\nnewline",
    ]
    for iid in invalid_ids:
        with pytest.raises(ValueError):
            validate_node_id(iid)


def test_read_only_client_mutation_lockdown():
    """Verifies that ReadOnlyGraphClient physically prevents any state-mutating operations."""
    client = FalkorGraphClient(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)
    ro_client = ReadOnlyGraphClient(client)

    # Read operations succeed
    paths = ro_client.discover_attack_paths("ci_runner")
    assert len(paths) == 3

    centrality = ro_client.get_betweenness_centrality()
    assert len(centrality) == len(seed.ALL_NODES)

    # Write operations MUST raise PermissionError
    with pytest.raises(PermissionError):
        ro_client.apply_containment_action(["deploy_token"])

    with pytest.raises(PermissionError):
        ro_client.inject_bypass_edge("ci_runner", "release_controller")

    with pytest.raises(PermissionError):
        ro_client.remove_bypass_edge("E-STRESS-BYPASS")

    with pytest.raises(PermissionError):
        ro_client.update_node_cost("release_controller", 5)


def test_live_query_telemetry_capture():
    """Verifies that FalkorDB query execution latency and exact Cypher are recorded."""
    client = FalkorGraphClient(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)
    client.discover_attack_paths("ci_runner")

    telemetry = client.last_telemetry
    assert telemetry is not None
    assert "MATCH p =" in telemetry.query
    assert telemetry.params == {"source_id": "ci_runner"}
    assert telemetry.latency_ms >= 0.0
    assert telemetry.client_latency_ms >= 0.0
    assert len(client.telemetry_history) >= 1


def test_judge_stress_testing_and_bypass_route():
    """
    Stress-testing verification:
    1. Initial paths = 3.
    2. Inject bypass edge directly to release_controller -> paths increase to 4.
    3. Remove bypass edge -> paths return to 3.
    """
    client = FalkorGraphClient(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)
    initial_paths = client.discover_attack_paths("ci_runner")
    assert len(initial_paths) == 3

    # Inject bypass route
    inj_mut = client.inject_bypass_edge("ci_runner", "release_controller")
    assert inj_mut.updated_edge_count == 1

    bypassed_paths = client.discover_attack_paths("ci_runner")
    assert len(bypassed_paths) == 4

    # Remove bypass route
    del_mut = client.remove_bypass_edge("E-STRESS-BYPASS")
    assert del_mut.updated_edge_count == 1

    restored_paths = client.discover_attack_paths("ci_runner")
    assert len(restored_paths) == 3


def test_dynamic_cost_mutation_and_optimizer_reaction():
    """
    Dynamically modifies release_controller cost from 10 to 3 in FalkorDB.
    Confirms that optimizer dynamically pivots from dual-token cut (cost 5)
    to single controller cut (cost 3).
    """
    client = FalkorGraphClient(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)
    service = ContainmentService(client=client)

    # Initial: release_controller cost 10 -> optimal plan is {deploy_token, artifact_token} (cost 5)
    res1 = service.analyze_incident()
    assert set(res1.recommended_plan.selected_node_ids) == {"deploy_token", "artifact_token"}
    assert res1.recommended_plan.total_cost == 5

    # Mutate release_controller cost to 3 in FalkorDB
    client.update_node_cost("release_controller", 3)

    # Re-run analysis: optimal plan must now be {release_controller} at cost 3
    res2 = service.analyze_incident()
    assert set(res2.recommended_plan.selected_node_ids) == {"release_controller"}
    assert res2.recommended_plan.total_cost == 3


def test_full_containment_lifecycle_and_clean_reset():
    """
    Mandatory Self-Verification Protocol (Part 4):
    1. Query initial attack paths (assert count > 0).
    2. Compute minimum-cost cut-set dynamically.
    3. Apply containment mutation in FalkorDB.
    4. Re-query attack paths (assert count == 0).
    5. Reset graph cleanly and verify pristine state.
    """
    service = ContainmentService(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)

    # 1. Query initial paths
    initial_analysis = service.analyze_incident()
    assert len(initial_analysis.discovered_paths) == 3

    # 2. Compute minimum-cost cut-set dynamically
    plan = initial_analysis.recommended_plan
    assert plan is not None
    assert set(plan.selected_node_ids) == {"deploy_token", "artifact_token"}
    assert plan.total_cost == 5

    # 3. Apply containment mutation
    mutation = service.validate_and_apply_plan(
        source_id="ci_runner",
        target_id="signing_key",
        expected_cut_ids=plan.selected_node_ids
    )
    assert mutation.updated_node_count == 2
    assert mutation.updated_edge_count > 0

    # 4. Re-query attack paths (assert count == 0)
    post_count = service.verify_containment_post_action(source_id="ci_runner")
    assert post_count == 0

    post_paths = service.client.discover_attack_paths("ci_runner")
    assert len(post_paths) == 0

    # 5. Reset graph cleanly
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)
    reset_paths = service.client.discover_attack_paths("ci_runner")
    assert len(reset_paths) == 3


def test_graph_computed_blast_radius():
    """
    UPGRADE 1: Confirms FalkorDB multi-hop reverse traversal dynamically derives
    blast radius disruption costs from downstream :Service impact scores:
    MATCH (s:Service)-[:DEPENDS_ON*1..4]->(e:Entity)
    """
    client = FalkorGraphClient(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)
    blast_map = client.compute_blast_radius(["deploy_token", "artifact_token", "release_controller"])

    assert "deploy_token" in blast_map
    assert blast_map["deploy_token"]["blast_radius_cost"] == 2
    assert "Staging Deployer" in blast_map["deploy_token"]["impacted_services"]

    assert "artifact_token" in blast_map
    assert blast_map["artifact_token"]["blast_radius_cost"] == 3
    assert "Artifact Publish Daemon" in blast_map["artifact_token"]["impacted_services"]

    assert "release_controller" in blast_map
    assert blast_map["release_controller"]["blast_radius_cost"] == 10
    assert blast_map["release_controller"]["downstream_service_count"] == 3
    assert "Checkout API" in blast_map["release_controller"]["impacted_services"]
    assert "Billing Worker" in blast_map["release_controller"]["impacted_services"]


def test_falkordb_multi_graph_smoking_mirror_isolation():
    """
    UPGRADE 2: Confirms FalkorDB multi-graph sandbox cloning into 'tezcatl_mirror'.
    Proves counterfactual containment in mirror without mutating prod_graph.
    """
    client = FalkorGraphClient(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)

    # Initial production paths = 3
    prod_paths_before = client.discover_attack_paths("ci_runner")
    assert len(prod_paths_before) == 3

    # Execute simulation in isolated tezcatl_mirror
    sim_res = client.simulate_mirror_containment(
        blocked_ids=["deploy_token", "artifact_token"],
        source_id="ci_runner"
    )

    assert sim_res["verified_contained"] is True
    assert sim_res["mirror_remaining_count"] == 0
    assert len(sim_res["mirror_paths"]) == 0
    assert sim_res["simulation_latency_ms"] >= 0.0

    # Crucial Isolation Check: prod_graph MUST remain completely unmutated!
    prod_paths_after = client.discover_attack_paths("ci_runner")
    assert len(prod_paths_after) == 3


def test_cryptographic_containment_receipt_and_hashes():
    """
    UPGRADE 3: Confirms generation of TEZCATL Containment Audit Receipt
    with distinct pre/post SHA-256 graph hashes, spared bottlenecks, and query telemetry.
    """
    service = ContainmentService(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)
    analysis = service.analyze_incident()
    plan = analysis.recommended_plan
    assert plan is not None

    mut, receipt = service.apply_and_audit_containment(
        source_id=analysis.source_id,
        target_id=analysis.target_id,
        expected_cut_ids=plan.selected_node_ids,
        incident_id="INC-TEST-RECEIPT-01"
    )

    assert receipt.verification_status == "CONTAINED_AND_VERIFIED"
    assert receipt.verified_remaining_paths == 0
    assert receipt.total_blast_radius_cost == 5
    assert len(receipt.optimal_cut_ids) == 2

    # Verify SHA-256 integrity hash divergence
    assert len(receipt.pre_mitigation_graph_hash) == 64
    assert len(receipt.post_mitigation_graph_hash) == 64
    assert receipt.pre_mitigation_graph_hash != receipt.post_mitigation_graph_hash

    # Verify high-centrality spared bottlenecks
    spared_ids = [b.node_id for b in receipt.spared_bottlenecks]
    assert "release_controller" in spared_ids
    controller_b = next(b for b in receipt.spared_bottlenecks if b.node_id == "release_controller")
    assert controller_b.blast_radius_cost == 10
    assert "Checkout API" in controller_b.services_preserved

    # Verify serializability
    json_str = receipt.to_json()
    assert "pre_mitigation_graph_hash" in json_str
    md_str = receipt.to_markdown()
    assert "# TEZCATL Containment Audit Receipt" in md_str
