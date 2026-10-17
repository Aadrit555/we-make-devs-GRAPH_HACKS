"""
TEZCATL — Graph-Native Security Containment Agent (FalkorDB)
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""

import pytest
import os
from config import settings
from graph_client import FalkorGraphClient, AttackPath, CentralityScore, MitigationCandidate
import seed

FALKORDB_HOST = settings.falkordb_host
FALKORDB_PORT = settings.falkordb_port
GRAPH_NAME = settings.falkordb_graph


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
    """Query 1: exactly two active directed paths from ci-runner-07 to prod-signing-key within 8 hops."""
    paths = client.discover_attack_paths("ci-runner-07", max_hops=8)
    assert isinstance(paths, list)
    assert len(paths) == 2

    for p in paths:
        assert isinstance(p, AttackPath)
        assert p.hops == 4
        assert p.node_ids[0] == "ci-runner-07"
        assert p.node_ids[-1] == "prod-signing-key"
        assert len(p.node_ids) == 5
        assert len(p.mechanisms) == 4
        assert len(p.evidence_ids) == 4


def test_path_correctness_and_expected_entities(client):
    """All 2 paths contain expected entities and follow active directed ATTACK_STEP relationships."""
    paths = client.discover_attack_paths("ci-runner-07")
    path_nodes = [p.node_ids for p in paths]

    expected_1 = ["ci-runner-07", "tok-artifact-rw", "pkg-registry-core", "release-controller", "prod-signing-key"]
    expected_2 = ["ci-runner-07", "tok-deploy-alpha", "role-cloud-deployer", "release-controller", "prod-signing-key"]

    assert expected_1 in path_nodes
    assert expected_2 in path_nodes


def test_evidence_integrity(client):
    """Returned edge mechanisms and evidence IDs match those seeded in FalkorDB."""
    paths = client.discover_attack_paths("ci-runner-07")
    artifact_path = next(p for p in paths if "tok-artifact-rw" in p.node_ids)

    # Check evidence IDs along the artifact path
    assert artifact_path.evidence_ids == ["E-002", "E-005", "E-007", "E-008"]
    assert artifact_path.mechanisms[0] == "Compromised runner accesses artifact token"
    assert artifact_path.mechanisms[1] == "Artifact token publishes to package registry"
    assert artifact_path.mechanisms[2] == "Package registry consumed by release controller"
    assert artifact_path.mechanisms[3] == "Release controller accesses production signing key"


def test_native_betweenness_centrality(client):
    """Native procedure executes successfully and returns valid numeric scores."""
    centrality = client.get_betweenness_centrality()
    assert isinstance(centrality, list)
    assert len(centrality) == len(seed.ALL_NODES)

    for item in centrality:
        assert isinstance(item, CentralityScore)
        assert isinstance(item.id, str) and len(item.id) > 0
        assert isinstance(item.score, float)
        assert item.score >= 0.0

    # release-controller is the primary choke point
    top_node_ids = [c.id for c in centrality[:2]]
    assert "release-controller" in top_node_ids


def test_candidate_retrieval_and_costs(client):
    """Candidate costs are read live from FalkorDB and exclude source and crown jewel."""
    paths = client.discover_attack_paths("ci-runner-07")
    all_path_nodes = sorted(list({node_id for p in paths for node_id in p.node_ids}))

    candidates = client.get_cut_candidates(all_path_nodes, source_id="ci-runner-07")
    cand_dict = {c.id: c.cost for c in candidates}

    # Protected endpoints must NOT be in candidates
    assert "ci-runner-07" not in cand_dict
    assert "prod-signing-key" not in cand_dict

    # Verified live costs (dynamic service impact / blast radius)
    assert cand_dict["tok-deploy-alpha"] == 2
    assert cand_dict["tok-artifact-rw"] == 3
    assert cand_dict["role-cloud-deployer"] == 5
    assert cand_dict["pkg-registry-core"] == 3
    assert cand_dict["release-controller"] == 14


def test_sandbox_verification(client):
    """
    Shadow-graph zero-path verification:
    - Excluding {tok-deploy-alpha, tok-artifact-rw} returns 0 remaining paths.
    - Excluding only {tok-deploy-alpha} leaves the artifact path (1 remaining path).
    - Excluding only {tok-artifact-rw} leaves the deploy path (1 remaining path).
    - Excluding {release-controller} alone returns 0 remaining paths.
    - Excluding nothing returns all 2 paths.
    """
    # Pristine: all 2 active
    assert client.count_remaining_paths("ci-runner-07", []) == 2

    # Both tokens severed -> exactly 0 paths
    assert client.count_remaining_paths("ci-runner-07", ["tok-deploy-alpha", "tok-artifact-rw"]) == 0

    # Only tok-deploy-alpha severed -> 1 path remaining (artifact route)
    assert client.count_remaining_paths("ci-runner-07", ["tok-deploy-alpha"]) == 1

    # Only tok-artifact-rw severed -> 1 path remaining (deploy route)
    assert client.count_remaining_paths("ci-runner-07", ["tok-artifact-rw"]) == 1

    # release-controller severed -> 0 paths remaining
    assert client.count_remaining_paths("ci-runner-07", ["release-controller"]) == 0


def test_database_failure_handling():
    """Unreachable FalkorDB host surfaces explicit connection error rather than fake empty result."""
    bad_client = FalkorGraphClient(host="127.0.0.1", port=6378, graph_name="nonexistent")
    with pytest.raises(Exception):
        bad_client.discover_attack_paths("ci-runner-07")
