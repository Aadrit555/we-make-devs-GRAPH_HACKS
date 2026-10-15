"""
tests/test_action_verification_integration.py — Live integration tests for Phase 4 human approval and verification loop.

Tests:
1. End-to-end incident analysis returning live paths and candidate costs.
2. Freshness revalidation rejecting stale plans if graph state has altered.
3. Actual graph mutation (Query 5) properly marking nodes disabled and edges inactive.
4. Post-action verification query confirming exactly 0 remaining paths.
5. Ineffective or partial mitigation rejection.
"""

import pytest
import os
from logic import ContainmentService, GraphFreshnessError
from config import settings
from graph_client import FalkorGraphClient
import seed

FALKORDB_HOST = settings.falkordb_host
FALKORDB_PORT = settings.falkordb_port
GRAPH_NAME = settings.falkordb_graph


@pytest.fixture(autouse=True)
def reset_demo_graph():
    """Ensure pristine graph before each test in this suite."""
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)


def test_end_to_end_approval_and_post_verification():
    """
    Complete closed-loop verification:
    1. Analyze incident -> 3 paths found, plan = {deploy_token, artifact_token} (cost 5).
    2. Validate freshness and apply containment.
    3. Run fresh post-action query against FalkorDB -> 0 paths remaining.
    """
    service = ContainmentService(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)
    res = service.analyze_incident()

    assert len(res.discovered_paths) == 3
    assert set(res.recommended_plan.selected_node_ids) == {"deploy_token", "artifact_token"}
    assert res.recommended_plan.total_cost == 5

    # Apply approved containment
    mutation = service.validate_and_apply_plan(
        source_id="ci_runner",
        target_id="signing_key",
        expected_cut_ids=res.recommended_plan.selected_node_ids
    )

    assert mutation.updated_node_count == 2
    assert set(mutation.disabled_ids) == {"deploy_token", "artifact_token"}
    assert mutation.updated_edge_count > 0

    # Fresh post-action verification query against actual mutated FalkorDB graph
    post_count = service.verify_containment_post_action(source_id="ci_runner")
    assert post_count == 0

    # Direct query check: active paths must be 0
    remaining_discovered = service.client.discover_attack_paths("ci_runner")
    assert len(remaining_discovered) == 0


def test_rejection_of_stale_or_ineffective_plan():
    """
    Freshness check must refuse to apply a plan if the proposed cut fails to sever all paths.
    E.g. proposing only {"deploy_token"} leaves the artifact route active.
    """
    service = ContainmentService(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)

    # Attempt to apply incomplete cut {"deploy_token"}
    with pytest.raises(GraphFreshnessError) as exc_info:
        service.validate_and_apply_plan(
            source_id="ci_runner",
            target_id="signing_key",
            expected_cut_ids=["deploy_token"]
        )

    assert "leaves 1 active paths" in str(exc_info.value)


def test_rejection_when_graph_already_contained():
    """
    If graph has already been contained, re-applying raises GraphFreshnessError.
    """
    service = ContainmentService(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)

    # Apply valid containment
    service.validate_and_apply_plan(
        source_id="ci_runner",
        target_id="signing_key",
        expected_cut_ids=["deploy_token", "artifact_token"]
    )

    # Attempting to re-apply should detect that no active paths remain
    with pytest.raises(GraphFreshnessError) as exc_info:
        service.validate_and_apply_plan(
            source_id="ci_runner",
            target_id="signing_key",
            expected_cut_ids=["deploy_token", "artifact_token"]
        )

    assert "no active attack paths exist currently" in str(exc_info.value)

