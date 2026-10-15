"""
tests/test_seed_integration.py - Integration tests for seed.py against live FalkorDB.
"""

import os
import pytest
from config import settings
from falkordb import FalkorDB
import seed

FALKORDB_HOST = settings.falkordb_host
FALKORDB_PORT = settings.falkordb_port
GRAPH_NAME = settings.falkordb_graph


@pytest.fixture(scope="module")
def graph():
    db = FalkorDB(host=FALKORDB_HOST, port=FALKORDB_PORT)
    g = db.select_graph(GRAPH_NAME)
    return g


def test_falkordb_connection_and_ping(graph):
    res = graph.query("RETURN 1 AS ping")
    assert res.result_set is not None
    assert len(res.result_set) == 1
    assert res.result_set[0][0] == 1


def test_seed_database_execution_and_counts(graph):
    # Execute seed
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)

    # Entity nodes
    node_res = graph.query("MATCH (n:Entity) RETURN count(n) AS cnt")
    assert node_res.result_set[0][0] == len(seed.ALL_NODES)

    # 10 ATTACK_STEP relationships
    attack_res = graph.query("MATCH ()-[r:ATTACK_STEP]->() RETURN count(r) AS cnt")
    assert attack_res.result_set[0][0] == len(seed.ATTACK_EDGES)

    # DEPENDS_ON relationships
    dep_res = graph.query("MATCH ()-[r:DEPENDS_ON]->() RETURN count(r) AS cnt")
    assert dep_res.result_set[0][0] == len(seed.ALL_DEPENDENCIES)


def test_entity_properties_and_types(graph):
    res = graph.query("""
        MATCH (n:Entity)
        RETURN n.id AS id, n.name AS name, n.kind AS kind,
               n.criticality AS criticality, n.cost AS cost, n.status AS status
    """)
    records = res.result_set
    assert len(records) == len(seed.ALL_NODES)

    allowed_kinds = {
        "workload", "credential", "iam_role", "registry", "service",
        "key", "session", "artifact", "cluster", "host", "trust_binding"
    }
    allowed_criticality = {"low", "medium", "high", "critical", "crown_jewel"}
    allowed_status = {"active", "compromised", "disabled"}

    for r in records:
        node_id, name, kind, criticality, cost, status = r
        assert isinstance(node_id, str) and len(node_id) > 0
        assert isinstance(name, str) and len(name) > 0
        assert kind in allowed_kinds
        assert criticality in allowed_criticality
        assert isinstance(cost, int) and cost >= 0
        assert status in allowed_status

    # Specific anchor tests
    runner = graph.query("MATCH (n:Entity {id: 'ci_runner'}) RETURN n.status, n.cost").result_set[0]
    assert runner[0] == "compromised"
    assert runner[1] == 10

    key = graph.query("MATCH (n:Entity {id: 'signing_key'}) RETURN n.criticality, n.cost").result_set[0]
    assert key[0] == "crown_jewel"
    assert key[1] == 9999


def test_attack_step_properties(graph):
    res = graph.query("""
        MATCH ()-[r:ATTACK_STEP]->()
        RETURN r.mechanism AS mechanism, r.active AS active, r.evidence_id AS evidence_id
    """)
    for r in res.result_set:
        mechanism, active, evidence_id = r
        assert isinstance(mechanism, str) and len(mechanism) > 0
        assert isinstance(active, bool)
        assert active is True
        assert isinstance(evidence_id, str) and evidence_id.startswith("E-")


def test_depends_on_properties(graph):
    res = graph.query("""
        MATCH ()-[r:DEPENDS_ON]->()
        RETURN r.purpose AS purpose
    """)
    for r in res.result_set:
        purpose = r[0]
        assert isinstance(purpose, str) and len(purpose) > 0


def test_reseeding_determinism(graph):
    # Run seed twice and verify exact node and edge counts are preserved
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=GRAPH_NAME)

    nodes = graph.query("MATCH (n:Entity) RETURN count(n)").result_set[0][0]
    attacks = graph.query("MATCH ()-[r:ATTACK_STEP]->() RETURN count(r)").result_set[0][0]
    deps = graph.query("MATCH ()-[r:DEPENDS_ON]->() RETURN count(r)").result_set[0][0]

    assert nodes == len(seed.ALL_NODES)
    assert attacks == len(seed.ATTACK_EDGES)
    assert deps == len(seed.ALL_DEPENDENCIES)


def test_intended_directed_attack_paths(graph):
    # Exactly three intended active directed paths from ci_runner to signing_key within 8 hops
    query = """
    MATCH p = (src:Entity {id: 'ci_runner'})-[:ATTACK_STEP*1..8]->(target:Entity {criticality: 'crown_jewel'})
    WHERE ALL(r IN relationships(p) WHERE r.active = true)
      AND ALL(n IN nodes(p) WHERE n.status <> 'disabled')
    RETURN [n IN nodes(p) | n.id] AS node_ids, length(p) AS hops
    ORDER BY hops ASC
    """
    res = graph.query(query)
    paths = res.result_set
    assert len(paths) == 3

    path_nodes = [p[0] for p in paths]
    expected_paths = [
        ["ci_runner", "artifact_token", "artifact_registry", "release_controller", "signer_role", "signing_key"],
        ["ci_runner", "deploy_token", "legacy_release_session", "release_controller", "signer_role", "signing_key"],
        ["ci_runner", "deploy_token", "production_deploy_role", "release_controller", "signer_role", "signing_key"],
    ]

    for ep in expected_paths:
        assert ep in path_nodes

    # All paths must be exactly 5 hops (length(p) == 5)
    for p in paths:
        assert p[1] == 5


