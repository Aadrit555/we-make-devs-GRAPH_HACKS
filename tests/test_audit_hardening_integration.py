"""
tests/test_audit_hardening_integration.py — Integration tests verifying Security Hardening,
Anti-Vibecode Refactor, Telemetry Instrumentation, and Read/Write Interface Segregation.
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
    assert len(centrality) == 16

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

    # Inject bypass
    mut = client.inject_bypass_edge("ci_runner", "release_controller", "E-STRESS-BYPASS")
    assert mut.updated_edge_count == 1

    expanded_paths = client.discover_attack_paths("ci_runner")
    assert len(expanded_paths) == 4

    # Remove bypass
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
