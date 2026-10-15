"""
tests/test_cut_set_calculator.py — Comprehensive tests for cut_set_calculator.py and logic.py.

Includes pure mathematical unit tests and live integration assertions against FalkorDB.
"""

import pytest
import os
from cut_set_calculator import (
    compute_minimum_cost_cut,
    CutPlan,
    NoValidCutError,
    CandidateCapExceededError,
    InvalidCandidateDataError,
)
from logic import ContainmentService
from graph_client import FalkorGraphClient
import seed

FALKORDB_HOST = os.getenv("FALKORDB_HOST", "127.0.0.1")
FALKORDB_PORT = int(os.getenv("FALKORDB_PORT", "6379"))
GRAPH_NAME = os.getenv("FALKORDB_GRAPH", "cutline_demo")


@pytest.fixture(scope="module", autouse=True)
def pristine_seed():
    """Ensure pristine seeded graph before running tests."""
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)


# ==============================================================================
# 1. Mandatory Optimality & Live Integration Tests
# ==============================================================================

def test_live_optimal_cut_and_cost_assertion():
    """
    Mandatory test:
    - Obtains live paths and candidate costs from FalkorDB.
    - Asserts total_cost == 5.
    - Asserts selected cut is exactly {"deploy_token", "artifact_token"}.
    """
    service = ContainmentService(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)
    res = service.analyze_incident()

    plan = res.recommended_plan
    assert plan is not None
    assert plan.total_cost == 5
    assert set(plan.action_ids) == {"deploy_token", "artifact_token"}
    assert plan.paths_evaluated_count == 3
    assert plan.paths_covered_count == 3
    assert res.counterfactual_remaining_paths == 0


def test_live_candidate_costs_from_database():
    """Candidate costs must match live FalkorDB properties: deploy=2, artifact=3, controller=10."""
    service = ContainmentService(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)
    res = service.analyze_incident()

    cost_map = {c.id: c.cost for c in res.eligible_candidates}
    assert cost_map["deploy_token"] == 2
    assert cost_map["artifact_token"] == 3
    assert cost_map["release_controller"] == 10
    assert cost_map["legacy_release_session"] == 4
    assert cost_map["production_deploy_role"] == 6
    assert cost_map["artifact_registry"] == 7
    assert cost_map["signer_role"] == 8


def test_suboptimal_release_controller_alone():
    """
    Disabling release_controller alone is a valid cut (it appears on all 3 paths),
    but costs 10, so the optimizer correctly rejects it in favor of cost 5.
    """
    client = FalkorGraphClient(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)
    paths = client.discover_attack_paths("ci_runner")
    path_nodes = [p.node_ids for p in paths]

    candidate_costs = {
        "deploy_token": 2,
        "artifact_token": 3,
        "release_controller": 10,
    }

    plan = compute_minimum_cost_cut(
        attack_paths=path_nodes,
        candidate_costs=candidate_costs,
        source_id="ci_runner",
        crown_jewel_ids={"signing_key"}
    )

    # Must pick cost 5, NOT cost 10
    assert plan.total_cost == 5
    assert set(plan.selected_node_ids) == {"deploy_token", "artifact_token"}

    # Counterfactual check: release_controller cuts all paths, but is more expensive
    assert client.count_remaining_paths("ci_runner", ["release_controller"]) == 0


def test_single_token_revocation_leaves_routes_open():
    """
    Confirming that disabling only one token fails to contain the incident:
    - Disabling deploy_token leaves artifact route.
    - Disabling artifact_token leaves 2 deployment routes.
    """
    client = FalkorGraphClient(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)
    assert client.count_remaining_paths("ci_runner", ["deploy_token"]) == 1
    assert client.count_remaining_paths("ci_runner", ["artifact_token"]) == 2


# ==============================================================================
# 2. Pure Algorithm Unit Tests
# ==============================================================================

def test_pure_cut_set_basic_three_paths():
    """Simulates the three paths with candidate costs in memory."""
    paths = [
        ["src", "a", "c", "ctrl", "tgt"],
        ["src", "b", "d", "ctrl", "tgt"],
        ["src", "x", "y", "ctrl", "tgt"],
    ]
    costs = {
        "a": 1,
        "b": 1,
        "x": 1,
        "ctrl": 10,
    }
    plan = compute_minimum_cost_cut(
        attack_paths=paths,
        candidate_costs=costs,
        source_id="src",
        crown_jewel_ids={"tgt"}
    )
    assert plan.total_cost == 3
    assert set(plan.selected_node_ids) == {"a", "b", "x"}


def test_protected_source_and_crown_jewel():
    """Source and crown jewel must never be selected even if they have cost 0."""
    paths = [["src", "step1", "tgt"]]
    costs = {
        "src": 0,
        "tgt": 0,
        "step1": 5,
    }
    plan = compute_minimum_cost_cut(
        attack_paths=paths,
        candidate_costs=costs,
        source_id="src",
        crown_jewel_ids={"tgt"}
    )
    assert set(plan.selected_node_ids) == {"step1"}
    assert plan.total_cost == 5


def test_empty_paths_returns_zero_plan():
    """If there are no attack paths, returns zero cost and empty plan."""
    plan = compute_minimum_cost_cut(
        attack_paths=[],
        candidate_costs={"a": 5},
        source_id="src",
        crown_jewel_ids={"tgt"}
    )
    assert plan.total_cost == 0
    assert plan.selected_node_ids == []
    assert plan.paths_evaluated_count == 0


def test_duplicate_paths_invariance():
    """Duplicated paths must not alter the optimal outcome."""
    paths = [
        ["src", "a", "tgt"],
        ["src", "a", "tgt"],
        ["src", "b", "tgt"],
    ]
    costs = {"a": 2, "b": 3}
    plan = compute_minimum_cost_cut(
        attack_paths=paths,
        candidate_costs=costs,
        source_id="src",
        crown_jewel_ids={"tgt"}
    )
    assert set(plan.selected_node_ids) == {"a", "b"}
    assert plan.total_cost == 5


def test_input_ordering_invariance():
    """Reversing the input candidate or path order yields the exact same deterministic plan."""
    paths1 = [["src", "a", "tgt"], ["src", "b", "tgt"]]
    paths2 = [["src", "b", "tgt"], ["src", "a", "tgt"]]

    costs1 = {"a": 2, "b": 2}
    costs2 = {"b": 2, "a": 2}

    plan1 = compute_minimum_cost_cut(paths1, costs1, source_id="src", crown_jewel_ids={"tgt"})
    plan2 = compute_minimum_cost_cut(paths2, costs2, source_id="src", crown_jewel_ids={"tgt"})

    assert plan1.selected_node_ids == plan2.selected_node_ids
    assert plan1.total_cost == plan2.total_cost


def test_tie_breaking_order():
    """
    Tie-breaking:
    1. Lower cost wins.
    2. Equal cost -> fewer nodes wins.
    3. Equal cost & node count -> lexicographical order wins.
    """
    # Two single-node cuts: "node_z" cost 5 vs "node_a" cost 5
    paths = [["src", "node_z", "node_a", "tgt"]]
    costs = {"node_z": 5, "node_a": 5}
    plan = compute_minimum_cost_cut(paths, costs, source_id="src", crown_jewel_ids={"tgt"})
    # "node_a" < "node_z" lexicographically
    assert plan.selected_node_ids == ["node_a"]

    # One 1-node cut cost 4 vs two 1-node cuts cost 2+2=4
    paths2 = [["src", "x", "tgt"], ["src", "y", "tgt"]]
    # Cut 1: {bridge} cost 4
    # Cut 2: {x, y} cost 2 + 2 = 4
    paths_bridge = [["src", "x", "bridge", "tgt"], ["src", "y", "bridge", "tgt"]]
    costs_bridge = {"bridge": 4, "x": 2, "y": 2}
    plan_bridge = compute_minimum_cost_cut(paths_bridge, costs_bridge, source_id="src", crown_jewel_ids={"tgt"})
    # {bridge} has size 1 vs {x, y} size 2 -> size 1 wins
    assert plan_bridge.selected_node_ids == ["bridge"]


def test_negative_cost_raises_error():
    """Negative candidate cost must raise InvalidCandidateDataError."""
    paths = [["src", "a", "tgt"]]
    with pytest.raises(InvalidCandidateDataError):
        compute_minimum_cost_cut(paths, {"a": -1})


def test_malformed_path_raises_error():
    """Path with < 2 nodes must raise InvalidCandidateDataError."""
    with pytest.raises(InvalidCandidateDataError):
        compute_minimum_cost_cut([["src"]], {"src": 1})


def test_infeasible_candidate_set_raises_error():
    """If candidates cannot sever all paths, raises NoValidCutError."""
    # Path 2 has no eligible candidate
    paths = [["src", "cand_a", "tgt"], ["src", "no_cand", "tgt"]]
    costs = {"cand_a": 1}
    with pytest.raises(NoValidCutError):
        compute_minimum_cost_cut(paths, costs, source_id="src", crown_jewel_ids={"tgt"})


def test_candidate_cap_enforcement():
    """Candidate count exceeding safety cap raises CandidateCapExceededError."""
    paths = [["src", f"node_{i}", "tgt"] for i in range(25)]
    costs = {f"node_{i}": 1 for i in range(25)}
    with pytest.raises(CandidateCapExceededError):
        compute_minimum_cost_cut(paths, costs, source_id="src", crown_jewel_ids={"tgt"}, max_candidate_cap=18)


def test_failure_closed_on_unreachable_db():
    """Logic layer fails closed if database is unavailable; never treats error as 0 paths."""
    bad_client = FalkorGraphClient(host="127.0.0.1", port=6378, graph_name="nonexistent")
    service = ContainmentService(client=bad_client)
    with pytest.raises(Exception):
        service.analyze_incident()

