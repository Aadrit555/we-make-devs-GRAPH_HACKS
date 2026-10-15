"""
tests/test_graph_engine_integration.py — Live integration tests for FalkorGraphClient.
Connects to live FalkorDB instance and tests all Phase 2 queries and assertions.
"""

import pytest
import os
from graph_client import FalkorGraphClient, AttackPath, CentralityScore, MitigationCandidate
import seed

FALKORDB_HOST = os.getenv("FALKORDB_HOST", "127.0.0.1")
FALKORDB_PORT = int(os.getenv("FALKORDB_PORT", "6379"))
GRAPH_NAME = os.getenv("FALKORDB_GRAPH", "cutline_demo")


@pytest.fixture(scope="module", autouse=True)
def ensure_seeded_graph():
    """Ensure pristine graph seed before running tests."""
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)


@pytest.fixture
def client():
    return FalkorGraphClient(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)


def test_client_connection(client):
    """Verify live connectivity check."""
    assert client.check_connection() is True


def test_path_discovery_count_and_hop_bound(client):
    """Query 1: exactly three active directed paths from ci_runner to signing_key within 8 hops."""
    paths = client.discover_attack_paths("ci_runner", max_hops=8)
    assert isinstance(paths, list)
    assert len(paths) == 3

    for p in paths:
        assert isinstance(p, AttackPath)
        assert p.hops == 5
        assert p.node_ids[0] == "ci_runner"
        assert p.node_ids[-1] == "signing_key"
        assert len(p.node_ids) == 6
        assert len(p.mechanisms) == 5
        assert len(p.evidence_ids) == 5


def test_path_correctness_and_expected_entities(client):
    """All 3 paths contain expected entities and follow active directed ATTACK_STEP relationships."""
    paths = client.discover_attack_paths("ci_runner")
    path_nodes = [p.node_ids for p in paths]

    expected_1 = ["ci_runner", "artifact_token", "artifact_registry", "release_controller", "signer_role", "signing_key"]
    expected_2 = ["ci_runner", "deploy_token", "legacy_release_session", "release_controller", "signer_role", "signing_key"]
    expected_3 = ["ci_runner", "deploy_token", "production_deploy_role", "release_controller", "signer_role", "signing_key"]

    assert expected_1 in path_nodes
    assert expected_2 in path_nodes
    assert expected_3 in path_nodes


def test_evidence_integrity(client):
    """Returned edge mechanisms and evidence IDs match those seeded in FalkorDB."""
    paths = client.discover_attack_paths("ci_runner")
    artifact_path = next(p for p in paths if "artifact_token" in p.node_ids)

    # Check evidence IDs along the artifact path
    assert artifact_path.evidence_ids == ["E-004", "E-005", "E-006", "E-009", "E-010"]
    assert artifact_path.mechanisms[0] == "Compromised runner can access registry credential"
    assert artifact_path.mechanisms[1] == "Credential has artifact publish permission"
    assert artifact_path.mechanisms[2] == "Controller consumes registry artifacts"
    assert artifact_path.mechanisms[3] == "Release controller can request signing"
    assert artifact_path.mechanisms[4] == "Signing role can use production key"


def test_native_betweenness_centrality(client):
    """Native procedure executes successfully and returns valid numeric scores."""
    centrality = client.get_betweenness_centrality()
    assert isinstance(centrality, list)
    assert len(centrality) == 16

    for item in centrality:
        assert isinstance(item, CentralityScore)
        assert isinstance(item.id, str) and len(item.id) > 0
        assert isinstance(item.score, float)
        assert item.score >= 0.0

    # release_controller and signer_role are prominent bridge nodes
    top_node_ids = [c.id for c in centrality[:2]]
    assert "release_controller" in top_node_ids


def test_candidate_retrieval_and_costs(client):
    """Candidate costs are read live from FalkorDB and exclude source and crown jewel."""
    paths = client.discover_attack_paths("ci_runner")
    all_path_nodes = sorted(list({node_id for p in paths for node_id in p.node_ids}))

    candidates = client.get_cut_candidates(all_path_nodes, source_id="ci_runner")
    cand_dict = {c.id: c.cost for c in candidates}

    # Protected endpoints must NOT be in candidates
    assert "ci_runner" not in cand_dict
    assert "signing_key" not in cand_dict

    # Verified live costs
    assert cand_dict["deploy_token"] == 2
    assert cand_dict["artifact_token"] == 3
    assert cand_dict["legacy_release_session"] == 4
    assert cand_dict["production_deploy_role"] == 6
    assert cand_dict["artifact_registry"] == 7
    assert cand_dict["signer_role"] == 8
    assert cand_dict["release_controller"] == 10


def test_counterfactual_verification(client):
    """
    Counterfactual zero-path verification:
    - Excluding {deploy_token, artifact_token} returns 0 remaining paths.
    - Excluding only {deploy_token} leaves the artifact path (1 remaining path).
    - Excluding only {artifact_token} leaves the two deploy paths (2 remaining paths).
    - Excluding {release_controller} alone returns 0 remaining paths.
    - Excluding nothing returns all 3 paths.
    """
    # Pristine: all 3 active
    assert client.count_remaining_paths("ci_runner", []) == 3

    # Both tokens severed -> exactly 0 paths
    assert client.count_remaining_paths("ci_runner", ["deploy_token", "artifact_token"]) == 0

    # Only deploy_token severed -> 1 path remaining (artifact route)
    assert client.count_remaining_paths("ci_runner", ["deploy_token"]) == 1

    # Only artifact_token severed -> 2 paths remaining (deploy routes)
    assert client.count_remaining_paths("ci_runner", ["artifact_token"]) == 2

    # release_controller severed -> 0 paths remaining
    assert client.count_remaining_paths("ci_runner", ["release_controller"]) == 0


def test_database_failure_handling():
    """Unreachable FalkorDB host surfaces explicit connection error rather than fake empty result."""
    bad_client = FalkorGraphClient(host="127.0.0.1", port=6378, graph_name="nonexistent")
    with pytest.raises(Exception):
        bad_client.discover_attack_paths("ci_runner")

