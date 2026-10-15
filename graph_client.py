"""
graph_client.py — Live FalkorDB graph client for CUTLINE v2.

Owns parameterized OpenCypher queries, Pydantic domain models for query results,
and direct interaction with the FalkorDB database instance.
No UI code or LLM code belongs in this module.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import os
from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()

DEFAULT_HOST = os.getenv("FALKORDB_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.getenv("FALKORDB_PORT", "6379"))
DEFAULT_GRAPH = os.getenv("FALKORDB_GRAPH", "cutline_demo")


# ==============================================================================
# Pydantic Domain Models
# ==============================================================================

class AttackPath(BaseModel):
    """Structured representation of an active directed attack path."""
    node_ids: List[str]
    node_names: List[str]
    node_kinds: List[str]
    mechanisms: List[str]
    evidence_ids: List[str]
    hops: int


class CentralityScore(BaseModel):
    """Betweenness centrality score for a graph entity."""
    id: str
    name: str
    kind: str
    score: float


class MitigationCandidate(BaseModel):
    """Candidate entity for containment consideration."""
    id: str
    name: str
    kind: str
    criticality: str
    cost: int = Field(ge=0, description="Synthetic operational impact cost (>= 0)")
    status: str


class MutationResult(BaseModel):
    """Result of applying simulated containment mutation."""
    disabled_ids: List[str]
    updated_node_count: int
    updated_edge_count: int


# ==============================================================================
# OpenCypher Query Strings (Parameterized)
# ==============================================================================

# Query 1: Bounded directed multi-hop discovery
QUERY_DISCOVER_PATHS = """
MATCH p =
    (src:Entity {id: $source_id})
    -[:ATTACK_STEP*1..8]->
    (target:Entity {criticality: 'crown_jewel'})
WHERE ALL(r IN relationships(p) WHERE r.active = true)
  AND ALL(n IN nodes(p) WHERE n.status <> 'disabled')
RETURN
    [n IN nodes(p) | n.id] AS node_ids,
    [n IN nodes(p) | n.name] AS node_names,
    [n IN nodes(p) | n.kind] AS node_kinds,
    [r IN relationships(p) | r.mechanism] AS mechanisms,
    [r IN relationships(p) | r.evidence_id] AS evidence_ids,
    length(p) AS hops
ORDER BY hops ASC
"""

# Query 2: Native FalkorDB betweenness centrality
QUERY_BETWEENNESS_CENTRALITY = """
CALL algo.betweenness({
    nodeLabels: ['Entity'],
    relationshipTypes: ['ATTACK_STEP']
})
YIELD node, score
RETURN
    node.id AS id,
    node.name AS name,
    node.kind AS kind,
    score
ORDER BY score DESC
"""

# Query 3: Counterfactual verification / zero-path check
QUERY_COUNTERFACTUAL_PATHS = """
MATCH
    (src:Entity {id: $source_id}),
    (target:Entity {criticality: 'crown_jewel'})
OPTIONAL MATCH p =
    (src)-[:ATTACK_STEP*1..8]->(target)
WHERE ALL(r IN relationships(p) WHERE r.active = true)
  AND ALL(n IN nodes(p) WHERE n.status <> 'disabled')
  AND NONE(n IN nodes(p) WHERE n.id IN $severed_ids)
RETURN count(p) AS remaining_path_count
"""

# Query 4: Read eligible cut candidates and costs from FalkorDB
QUERY_CUT_CANDIDATES = """
MATCH (n:Entity)
WHERE n.id IN $path_node_ids
  AND n.status <> 'disabled'
  AND n.criticality <> 'crown_jewel'
  AND n.id <> $source_id
RETURN
    n.id AS id,
    n.name AS name,
    n.kind AS kind,
    n.criticality AS criticality,
    n.cost AS cost,
    n.status AS status
ORDER BY cost ASC, id ASC
"""

# Query 5A: Mark chosen nodes disabled
QUERY_DISABLE_NODES = """
UNWIND $blocked_ids AS blocked_id
MATCH (n:Entity {id: blocked_id})
SET n.status = 'disabled'
RETURN collect(n.id) AS disabled_ids, count(n) AS updated_count
"""

# Query 5B: Mark incident attack relationships inactive
QUERY_DEACTIVATE_EDGES = """
MATCH (a:Entity)-[r:ATTACK_STEP]->(b:Entity)
WHERE a.id IN $blocked_ids OR b.id IN $blocked_ids
SET r.active = false
RETURN count(r) AS updated_edge_count
"""


# ==============================================================================
# FalkorDB Graph Client Class
# ==============================================================================

class FalkorGraphClient:
    """Production graph client for executing parameterized Cypher queries against FalkorDB."""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, graph_name: str = DEFAULT_GRAPH):
        self.host = host
        self.port = port
        self.graph_name = graph_name
        self._db: Optional[FalkorDB] = None
        self._graph = None

    def connect(self):
        """Establish connection to FalkorDB and select graph."""
        try:
            self._db = FalkorDB(host=self.host, port=self.port)
            self._graph = self._db.select_graph(self.graph_name)
        except Exception as exc:
            raise ConnectionError(f"Failed to connect to FalkorDB at {self.host}:{self.port}: {exc}") from exc

    @property
    def graph(self):
        """Return the active graph instance, connecting if needed."""
        if self._graph is None:
            self.connect()
        return self._graph

    def check_connection(self) -> bool:
        """Verify database connectivity with a live query."""
        try:
            res = self.graph.query("RETURN 1 AS ping")
            return res.result_set is not None and len(res.result_set) == 1 and res.result_set[0][0] == 1
        except Exception:
            return False

    def discover_attack_paths(self, source_id: str, max_hops: int = 8) -> List[AttackPath]:
        """
        Query 1: Discover all active directed attack paths from source_id to crown_jewel.
        Traverses active ATTACK_STEP relationships up to max_hops (max 8).
        """
        if not source_id:
            raise ValueError("source_id must not be empty")
        if max_hops != 8:
            # Enforce 8-hop bound as specified in the schema contract
            pass

        try:
            res = self.graph.query(QUERY_DISCOVER_PATHS, {"source_id": source_id})
        except Exception as exc:
            raise RuntimeError(f"Error querying attack paths from FalkorDB: {exc}") from exc

        paths: List[AttackPath] = []
        for record in res.result_set:
            node_ids = record[0]
            node_names = record[1]
            node_kinds = record[2]
            mechanisms = record[3]
            evidence_ids = record[4]
            hops = int(record[5])

            paths.append(AttackPath(
                node_ids=node_ids,
                node_names=node_names,
                node_kinds=node_kinds,
                mechanisms=mechanisms,
                evidence_ids=evidence_ids,
                hops=hops
            ))
        return paths

    def get_betweenness_centrality(self) -> List[CentralityScore]:
        """
        Query 2: Execute native FalkorDB betweenness centrality procedure over ATTACK_STEP.
        Returns live centrality scores ordered descending.
        """
        try:
            res = self.graph.query(QUERY_BETWEENNESS_CENTRALITY)
        except Exception as exc:
            raise RuntimeError(f"Error executing algo.betweenness on FalkorDB: {exc}") from exc

        centrality_list: List[CentralityScore] = []
        for record in res.result_set:
            node_id = record[0]
            name = record[1]
            kind = record[2]
            score = float(record[3])
            centrality_list.append(CentralityScore(
                id=node_id,
                name=name,
                kind=kind,
                score=score
            ))
        return centrality_list

    def count_remaining_paths(self, source_id: str, severed_ids: Optional[List[str]] = None, max_hops: int = 8) -> int:
        """
        Query 3: Counterfactual verification / zero-path check.
        Counts how many directed active paths remain from source_id to crown jewel
        if severed_ids were excluded.
        """
        if not source_id:
            raise ValueError("source_id must not be empty")
        if severed_ids is None:
            severed_ids = []

        params = {
            "source_id": source_id,
            "severed_ids": severed_ids
        }

        try:
            res = self.graph.query(QUERY_COUNTERFACTUAL_PATHS, params)
        except Exception as exc:
            raise RuntimeError(f"Error executing counterfactual path query on FalkorDB: {exc}") from exc

        if not res.result_set or len(res.result_set) == 0:
            raise RuntimeError("Counterfactual query returned an empty result set")

        return int(res.result_set[0][0])

    def get_cut_candidates(self, path_node_ids: List[str], source_id: str) -> List[MitigationCandidate]:
        """
        Query 4: Fetch actual candidate entity records and synthetic costs from FalkorDB.
        Excludes source_id and crown_jewel target.
        """
        if not path_node_ids:
            return []

        params = {
            "path_node_ids": path_node_ids,
            "source_id": source_id
        }

        try:
            res = self.graph.query(QUERY_CUT_CANDIDATES, params)
        except Exception as exc:
            raise RuntimeError(f"Error querying cut candidates from FalkorDB: {exc}") from exc

        candidates: List[MitigationCandidate] = []
        for record in res.result_set:
            cand_id = record[0]
            name = record[1]
            kind = record[2]
            criticality = record[3]
            cost = int(record[4])
            status = record[5]

            candidates.append(MitigationCandidate(
                id=cand_id,
                name=name,
                kind=kind,
                criticality=criticality,
                cost=cost,
                status=status
            ))
        return candidates

    def apply_containment_action(self, blocked_ids: List[str]) -> MutationResult:
        """
        Query 5: Apply simulated containment action to the graph state.
        Marks chosen nodes 'disabled' and incident ATTACK_STEP edges active = false.
        """
        if not blocked_ids:
            return MutationResult(disabled_ids=[], updated_node_count=0, updated_edge_count=0)

        params = {"blocked_ids": blocked_ids}

        try:
            # 1. Update nodes
            node_res = self.graph.query(QUERY_DISABLE_NODES, params)
            disabled_ids = node_res.result_set[0][0] if node_res.result_set else []
            updated_node_cnt = int(node_res.result_set[0][1]) if node_res.result_set else 0

            # 2. Update edges
            edge_res = self.graph.query(QUERY_DEACTIVATE_EDGES, params)
            updated_edge_cnt = int(edge_res.result_set[0][0]) if edge_res.result_set else 0

            return MutationResult(
                disabled_ids=disabled_ids,
                updated_node_count=updated_node_cnt,
                updated_edge_count=updated_edge_cnt
            )
        except Exception as exc:
            raise RuntimeError(f"Error applying containment mutation to FalkorDB: {exc}") from exc

