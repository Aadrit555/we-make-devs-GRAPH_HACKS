"""
graph_client.py — Hardened FalkorDB graph client for TEZCATL.

Owns parameterized OpenCypher queries, Pydantic domain models with strict validation,
query telemetry instrumentation, blast radius calculus, multi-graph mirror sandbox,
and read/write interface segregation.
No UI or LLM logic belongs in this module.
"""

import re
import time
import hashlib
import json
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from falkordb import FalkorDB
from config import settings

DEFAULT_HOST = settings.falkordb_host
DEFAULT_PORT = settings.falkordb_port
DEFAULT_GRAPH = settings.falkordb_graph
DEFAULT_MIRROR_GRAPH = settings.falkordb_mirror_graph

# Strict node ID validation regex: alphanumeric, underscores, hyphens; 1 to 64 chars
NODE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def validate_node_id(node_id: str) -> str:
    """Validate entity identifier against strict security regex before passing to graph."""
    if not isinstance(node_id, str) or not NODE_ID_REGEX.match(node_id):
        raise ValueError(
            f"Invalid node identifier '{node_id}'. Must be 1-64 alphanumeric, underscore, or hyphen characters."
        )
    return node_id


# ==============================================================================
# Typed Exceptions
# ==============================================================================

class DatabaseConnectionError(ConnectionError):
    """Raised when FalkorDB host is unreachable or disconnected."""
    def __init__(self, message: str):
        super().__init__(message)


class GraphQueryError(RuntimeError):
    """Raised when a Cypher query fails execution on FalkorDB."""
    def __init__(self, message: str):
        super().__init__(message)


class EvidenceUnavailableError(RuntimeError):
    """Raised when graph evidence or expected query result sets are missing."""
    def __init__(self, message: str):
        super().__init__(message)


# ==============================================================================
# Pydantic Domain & Telemetry Models (Strict: extra="forbid")
# ==============================================================================

class QueryTelemetry(BaseModel):
    """Execution telemetry captured directly from live FalkorDB query execution."""
    model_config = ConfigDict(extra="forbid")

    query: str
    params: Dict[str, Any]
    latency_ms: float = Field(ge=0.0, description="Internal execution time reported by FalkorDB (ms)")
    client_latency_ms: float = Field(ge=0.0, description="Client roundtrip execution latency (ms)")
    nodes_created: int = Field(default=0, ge=0)
    nodes_deleted: int = Field(default=0, ge=0)
    relationships_created: int = Field(default=0, ge=0)
    relationships_deleted: int = Field(default=0, ge=0)
    properties_set: int = Field(default=0, ge=0)
    raw_stats: List[str] = Field(default_factory=list)


class AttackPath(BaseModel):
    """Structured representation of an active directed attack path."""
    model_config = ConfigDict(extra="forbid")

    node_ids: List[str]
    node_names: List[str]
    node_kinds: List[str]
    mechanisms: List[str]
    evidence_ids: List[str]
    hops: int = Field(ge=1, le=8)


class CentralityScore(BaseModel):
    """Betweenness centrality score for a graph entity."""
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    name: str
    kind: str
    score: float = Field(ge=0.0)


class MitigationCandidate(BaseModel):
    """Candidate entity for containment consideration with graph-computed blast radius."""
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    name: str
    kind: str
    criticality: str
    cost: int = Field(ge=0, description="Operational blast-radius impact cost (>= 0)")
    status: str
    downstream_services: List[str] = Field(
        default_factory=list,
        description="Downstream services dynamically dependent on this entity"
    )
    downstream_count: int = Field(
        default=0,
        ge=0,
        description="Number of unique downstream services affected"
    )


class MutationResult(BaseModel):
    """Result of applying simulated containment or test topology mutation."""
    model_config = ConfigDict(extra="forbid")

    disabled_ids: List[str]
    updated_node_count: int = Field(ge=0)
    updated_edge_count: int = Field(ge=0)


# ==============================================================================
# OpenCypher Query Strings (100% Parameterized — Zero Interpolation)
# ==============================================================================

# Query 1A: Crown jewel bounded directed multi-hop discovery
QUERY_DISCOVER_PATHS_CROWN_JEWEL = """
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

# Query 1B: Specific target bounded directed multi-hop discovery
QUERY_DISCOVER_PATHS_TARGET = """
MATCH p =
    (src:Entity {id: $source_id})
    -[:ATTACK_STEP*1..8]->
    (target:Entity {id: $target_id})
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

# Query 3A: Counterfactual verification / zero-path check (crown jewel default)
QUERY_COUNTERFACTUAL_PATHS_CROWN_JEWEL = """
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

# Query 3B: Counterfactual verification / zero-path check (explicit target)
QUERY_COUNTERFACTUAL_PATHS_TARGET = """
MATCH
    (src:Entity {id: $source_id}),
    (target:Entity {id: $target_id})
OPTIONAL MATCH p =
    (src)-[:ATTACK_STEP*1..8]->(target)
WHERE ALL(r IN relationships(p) WHERE r.active = true)
  AND ALL(n IN nodes(p) WHERE n.status <> 'disabled')
  AND NONE(n IN nodes(p) WHERE n.id IN $severed_ids)
RETURN count(p) AS remaining_path_count
"""

# Query 4: Read eligible cut candidates from FalkorDB
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

# Query 6: Blast Radius Calculus (dynamic reverse multi-hop dependency traversal)
QUERY_COMPUTE_BLAST_RADIUS_CANDIDATES = """
MATCH (s:Service)-[:DEPENDS_ON*1..4]->(e:Entity)
WHERE e.id IN $candidate_ids
RETURN
    e.id AS entity_id,
    count(DISTINCT s) AS downstream_service_count,
    sum(s.revenue_impact_score) AS blast_radius_cost,
    collect(DISTINCT s.name) AS impacted_services
ORDER BY blast_radius_cost ASC, entity_id ASC
"""

QUERY_COMPUTE_BLAST_RADIUS_ALL = """
MATCH (s:Service)-[:DEPENDS_ON*1..4]->(e:Entity)
RETURN
    e.id AS entity_id,
    count(DISTINCT s) AS downstream_service_count,
    sum(s.revenue_impact_score) AS blast_radius_cost,
    collect(DISTINCT s.name) AS impacted_services
ORDER BY blast_radius_cost ASC, entity_id ASC
"""

# Query 7: Cloning & Mirror Sandbox Queries (100% Parameterized)
QUERY_ALL_NODES = """
MATCH (n:Entity)
RETURN
    n.id AS id,
    n.name AS name,
    n.kind AS kind,
    n.criticality AS criticality,
    n.cost AS cost,
    n.revenue_impact_score AS revenue_impact_score,
    n.status AS status,
    labels(n) AS labels
ORDER BY n.id ASC
"""

QUERY_ALL_EDGES = """
MATCH (a:Entity)-[r]->(b:Entity)
RETURN
    a.id AS src_id,
    b.id AS dst_id,
    type(r) AS rel_type,
    r.active AS active,
    r.mechanism AS mechanism,
    r.evidence_id AS evidence_id
ORDER BY a.id ASC, b.id ASC, rel_type ASC
"""

QUERY_CLONE_RESET = """
MATCH (n) DETACH DELETE n
"""

QUERY_CLONE_CREATE_NODES = """
UNWIND $nodes AS nd
CREATE (n:Entity {
    id: nd.id,
    name: nd.name,
    kind: nd.kind,
    criticality: nd.criticality,
    cost: nd.cost,
    revenue_impact_score: nd.revenue_impact_score,
    status: nd.status
})
"""

QUERY_CLONE_SET_SERVICES = """
UNWIND $service_ids AS sid
MATCH (n:Entity {id: sid})
SET n:Service
"""

QUERY_CLONE_CREATE_ATTACK_EDGES = """
UNWIND $edges AS ed
MATCH (a:Entity {id: ed.src})
MATCH (b:Entity {id: ed.dst})
CREATE (a)-[:ATTACK_STEP {
    active: ed.active,
    mechanism: ed.mechanism,
    evidence_id: ed.evidence_id
}]->(b)
"""

QUERY_CLONE_CREATE_DEPENDS_ON_EDGES = """
UNWIND $deps AS dp
MATCH (a:Entity {id: dp.src})
MATCH (b:Entity {id: dp.dst})
CREATE (a)-[:DEPENDS_ON]->(b)
"""

# Query 8: Cryptographic State Hash Queries
QUERY_GRAPH_NODES_STATE = """
MATCH (n:Entity)
RETURN n.id AS id, n.status AS status, n.cost AS cost
ORDER BY n.id ASC
"""

QUERY_GRAPH_EDGES_STATE = """
MATCH (a:Entity)-[r:ATTACK_STEP]->(b:Entity)
RETURN a.id AS src, b.id AS dst, r.active AS active
ORDER BY a.id ASC, b.id ASC
"""

# Stress-testing queries (strictly parameterized)
QUERY_LIST_ENTITIES = """
MATCH (n:Entity)
RETURN
    n.id AS id,
    n.name AS name,
    n.kind AS kind,
    n.criticality AS criticality,
    n.cost AS cost,
    n.status AS status
ORDER BY n.id ASC
"""

QUERY_INJECT_BYPASS_EDGE = """
MATCH (src:Entity {id: $source_id})
MATCH (dst:Entity {id: $target_id})
CREATE (src)-[r:ATTACK_STEP {
    mechanism: 'Injected stress-test bypass route',
    active: true,
    evidence_id: $evidence_id
}]->(dst)
RETURN count(r) AS edges_created
"""

QUERY_REMOVE_BYPASS_EDGE = """
MATCH ()-[r:ATTACK_STEP {evidence_id: $evidence_id}]->()
DELETE r
RETURN count(r) AS edges_deleted
"""

QUERY_UPDATE_NODE_COST = """
MATCH (n:Entity {id: $node_id})
SET n.cost = $new_cost
RETURN n.id AS id, n.cost AS cost
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
        self.last_telemetry: Optional[QueryTelemetry] = None
        self.telemetry_history: List[QueryTelemetry] = []

    def connect(self):
        """Establish connection to FalkorDB and select graph."""
        try:
            self._db = FalkorDB(host=self.host, port=self.port)
            self._graph = self._db.select_graph(self.graph_name)
        except Exception as exc:
            raise DatabaseConnectionError(f"Failed to connect to FalkorDB at {self.host}:{self.port}: {exc}") from exc

    @property
    def graph(self):
        """Return the active graph instance, connecting if needed."""
        if self._graph is None:
            self.connect()
        return self._graph

    def check_connection(self) -> bool:
        """Verify database connectivity with a live ping query."""
        try:
            res = self.graph.query("RETURN 1 AS ping")
            return res.result_set is not None and len(res.result_set) == 1 and res.result_set[0][0] == 1
        except Exception:
            return False

    def _execute_query(
        self,
        query: str,
        params: Optional[Dict[str, Any]] = None,
        read_only: bool = False
    ):
        """
        Internal execution wrapper that captures live FalkorDB telemetry and measures latency.
        Guarantees strictly typed error handling and zero silent fallbacks.
        """
        start_client_time = time.perf_counter()
        clean_params = params or {}

        try:
            res = self.graph.query(query, clean_params)
        except Exception as exc:
            raise GraphQueryError(f"FalkorDB query execution failed: {exc}") from exc

        client_duration_ms = (time.perf_counter() - start_client_time) * 1000.0
        internal_runtime_ms = getattr(res, "run_time_ms", client_duration_ms) or client_duration_ms

        telemetry = QueryTelemetry(
            query=query.strip(),
            params=clean_params,
            latency_ms=round(float(internal_runtime_ms), 4),
            client_latency_ms=round(float(client_duration_ms), 4),
            nodes_created=int(getattr(res, "nodes_created", 0) or 0),
            nodes_deleted=int(getattr(res, "nodes_deleted", 0) or 0),
            relationships_created=int(getattr(res, "relationships_created", 0) or 0),
            relationships_deleted=int(getattr(res, "relationships_deleted", 0) or 0),
            properties_set=int(getattr(res, "properties_set", 0) or 0),
            raw_stats=list(getattr(res, "_raw_stats", []) or [])
        )
        self.last_telemetry = telemetry
        self.telemetry_history.append(telemetry)
        return res

    def discover_attack_paths(
        self,
        source_id: str,
        target_id: Optional[str] = None,
        max_hops: int = 8
    ) -> List[AttackPath]:
        """
        Query 1: Discover all active directed attack paths from source_id within max_hops.
        If target_id is omitted, discovers paths to crown_jewel entities.
        """
        validate_node_id(source_id)
        if target_id is not None:
            validate_node_id(target_id)
        if max_hops < 1 or max_hops > 8:
            raise ValueError(f"max_hops must be between 1 and 8, got {max_hops}")

        if target_id:
            query = QUERY_DISCOVER_PATHS_TARGET
            params = {"source_id": source_id, "target_id": target_id}
        else:
            query = QUERY_DISCOVER_PATHS_CROWN_JEWEL
            params = {"source_id": source_id}

        res = self._execute_query(query, params, read_only=True)

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
        res = self._execute_query(QUERY_BETWEENNESS_CENTRALITY, read_only=True)

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

    def count_remaining_paths(
        self,
        source_id: str,
        severed_ids: Optional[List[str]] = None,
        target_id: Optional[str] = None,
        max_hops: int = 8
    ) -> int:
        """
        Query 3: Counterfactual verification / zero-path check.
        Counts how many directed active paths remain from source_id to target/crown jewel
        if severed_ids were excluded.
        """
        validate_node_id(source_id)
        if target_id is not None:
            validate_node_id(target_id)
        if max_hops < 1 or max_hops > 8:
            raise ValueError(f"max_hops must be between 1 and 8, got {max_hops}")

        clean_severed = [validate_node_id(sid) for sid in (severed_ids or [])]

        if target_id:
            query = QUERY_COUNTERFACTUAL_PATHS_TARGET
            params = {
                "source_id": source_id,
                "target_id": target_id,
                "severed_ids": clean_severed
            }
        else:
            query = QUERY_COUNTERFACTUAL_PATHS_CROWN_JEWEL
            params = {
                "source_id": source_id,
                "severed_ids": clean_severed
            }

        res = self._execute_query(query, params, read_only=True)

        if not res.result_set or len(res.result_set) == 0:
            raise EvidenceUnavailableError("Counterfactual query returned an empty result set.")

        return int(res.result_set[0][0])

    def compute_blast_radius(self, candidate_ids: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
        """
        Query 6: Dynamically compute operational blast radius via reverse graph traversal:
        MATCH (s:Service)-[:DEPENDS_ON*1..4]->(e:Entity)
        Calculates live blast_radius_cost as the sum of unique downstream :Service revenue_impact_scores.
        """
        if candidate_ids is not None:
            clean_ids = [validate_node_id(cid) for cid in candidate_ids]
            if not clean_ids:
                return {}
            query = QUERY_COMPUTE_BLAST_RADIUS_CANDIDATES
            params = {"candidate_ids": clean_ids}
        else:
            query = QUERY_COMPUTE_BLAST_RADIUS_ALL
            params = {}

        res = self._execute_query(query, params, read_only=True)

        blast_map: Dict[str, Dict[str, Any]] = {}
        for record in res.result_set:
            entity_id = record[0]
            downstream_count = int(record[1])
            blast_cost = int(record[2]) if record[2] is not None else 0
            impacted_services = list(record[3]) if record[3] is not None else []
            blast_map[entity_id] = {
                "entity_id": entity_id,
                "downstream_service_count": downstream_count,
                "blast_radius_cost": blast_cost,
                "impacted_services": impacted_services
            }
        return blast_map

    def get_cut_candidates(self, path_node_ids: List[str], source_id: str) -> List[MitigationCandidate]:
        """
        Query 4 & 6: Fetch eligible cut candidates and dynamically calculate their
        operational blast radius costs via reverse multi-hop dependency traversal in FalkorDB.
        Excludes source_id and crown_jewel target.
        """
        validate_node_id(source_id)
        if not path_node_ids:
            return []

        clean_path_node_ids = [validate_node_id(nid) for nid in path_node_ids]
        params = {
            "path_node_ids": clean_path_node_ids,
            "source_id": source_id
        }

        res = self._execute_query(QUERY_CUT_CANDIDATES, params, read_only=True)

        # Retrieve dynamic blast radius for all candidates
        candidate_ids = [record[0] for record in res.result_set]
        blast_info = self.compute_blast_radius(candidate_ids)

        candidates: List[MitigationCandidate] = []
        for record in res.result_set:
            cand_id = record[0]
            name = record[1]
            kind = record[2]
            criticality = record[3]
            raw_cost = int(record[4])
            status = record[5]

            # Use graph-computed blast radius cost if services depend on this entity
            if cand_id in blast_info and blast_info[cand_id]["blast_radius_cost"] > 0:
                cost = blast_info[cand_id]["blast_radius_cost"]
                downstream_services = blast_info[cand_id]["impacted_services"]
                downstream_count = blast_info[cand_id]["downstream_service_count"]
            else:
                cost = raw_cost
                downstream_services = []
                downstream_count = 0

            candidates.append(MitigationCandidate(
                id=cand_id,
                name=name,
                kind=kind,
                criticality=criticality,
                cost=cost,
                status=status,
                downstream_services=downstream_services,
                downstream_count=downstream_count
            ))
        return candidates

    def apply_containment_action(self, blocked_ids: List[str]) -> MutationResult:
        """
        Query 5: Apply simulated containment action to the graph state.
        Marks chosen nodes 'disabled' and incident ATTACK_STEP edges active = false.
        This state mutation is strictly write-gated behind explicit human approval.
        """
        if not blocked_ids:
            return MutationResult(disabled_ids=[], updated_node_count=0, updated_edge_count=0)

        clean_blocked_ids = [validate_node_id(bid) for bid in blocked_ids]
        params = {"blocked_ids": clean_blocked_ids}

        # 1. Update nodes
        node_res = self._execute_query(QUERY_DISABLE_NODES, params, read_only=False)
        disabled_ids = node_res.result_set[0][0] if node_res.result_set else []
        updated_node_cnt = int(node_res.result_set[0][1]) if node_res.result_set else 0

        # 2. Update edges
        edge_res = self._execute_query(QUERY_DEACTIVATE_EDGES, params, read_only=False)
        updated_edge_cnt = int(edge_res.result_set[0][0]) if edge_res.result_set else 0

        return MutationResult(
            disabled_ids=disabled_ids,
            updated_node_count=updated_node_cnt,
            updated_edge_count=updated_edge_cnt
        )

    # --------------------------------------------------------------------------
    # Multi-Graph "Smoking Mirror" Sandbox Cloning & Simulation
    # --------------------------------------------------------------------------

    def clone_to_mirror(self, mirror_graph_name: Optional[str] = None) -> "FalkorGraphClient":
        """
        Clones active topology from production graph into an isolated FalkorDB graph
        (e.g., 'tezcatl_mirror') using 100% parameterized queries.
        """
        target_name = mirror_graph_name or DEFAULT_MIRROR_GRAPH
        if target_name == self.graph_name:
            raise ValueError("Mirror graph name cannot match production graph name.")

        # Read active nodes and relationships from production
        nodes_res = self._execute_query(QUERY_ALL_NODES, read_only=True)
        edges_res = self._execute_query(QUERY_ALL_EDGES, read_only=True)

        mirror_client = FalkorGraphClient(host=self.host, port=self.port, graph_name=target_name)
        mirror_client.connect()

        # 1. Clear target mirror graph
        mirror_client._execute_query(QUERY_CLONE_RESET, read_only=False)

        # 2. Prepare nodes payload
        nodes_payload = []
        service_ids = []
        for r in nodes_res.result_set:
            node_dict = {
                "id": r[0],
                "name": r[1],
                "kind": r[2],
                "criticality": r[3],
                "cost": int(r[4]),
                "revenue_impact_score": int(r[5]) if r[5] is not None else 0,
                "status": r[6]
            }
            nodes_payload.append(node_dict)
            labels = r[7] if len(r) > 7 and r[7] else []
            if "Service" in labels:
                service_ids.append(r[0])

        if nodes_payload:
            mirror_client._execute_query(QUERY_CLONE_CREATE_NODES, {"nodes": nodes_payload}, read_only=False)

        if service_ids:
            mirror_client._execute_query(QUERY_CLONE_SET_SERVICES, {"service_ids": service_ids}, read_only=False)

        # 3. Prepare edges payload
        attack_edges = []
        deps_edges = []
        for r in edges_res.result_set:
            src_id, dst_id, rel_type, active, mechanism, evidence_id = r
            if rel_type == "ATTACK_STEP":
                attack_edges.append({
                    "src": src_id,
                    "dst": dst_id,
                    "active": bool(active),
                    "mechanism": mechanism or "",
                    "evidence_id": evidence_id or ""
                })
            elif rel_type == "DEPENDS_ON":
                deps_edges.append({
                    "src": src_id,
                    "dst": dst_id
                })

        if attack_edges:
            mirror_client._execute_query(QUERY_CLONE_CREATE_ATTACK_EDGES, {"edges": attack_edges}, read_only=False)

        if deps_edges:
            mirror_client._execute_query(QUERY_CLONE_CREATE_DEPENDS_ON_EDGES, {"deps": deps_edges}, read_only=False)

        return mirror_client

    def simulate_mirror_containment(
        self,
        blocked_ids: List[str],
        source_id: str = "ci_runner",
        target_id: Optional[str] = None,
        max_hops: int = 8,
        mirror_graph_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes candidate containment inside the isolated FalkorDB 'tezcatl_mirror' graph.
        Verifies 0 remaining paths and calculates counterfactual betweenness centrality
        without mutating the production graph.
        """
        start_time = time.perf_counter()
        target_name = mirror_graph_name or DEFAULT_MIRROR_GRAPH

        # 1. Clone production to mirror
        mirror_client = self.clone_to_mirror(mirror_graph_name=target_name)

        # 2. Mutate mirror only
        mutation_result = mirror_client.apply_containment_action(blocked_ids)

        # 3. Discover remaining paths in mirror
        mirror_paths = mirror_client.discover_attack_paths(
            source_id=source_id,
            target_id=target_id,
            max_hops=max_hops
        )

        # 4. Compute centrality in mirror
        mirror_centrality = mirror_client.get_betweenness_centrality()

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        return {
            "mirror_graph_name": target_name,
            "blocked_ids": blocked_ids,
            "mutation_result": mutation_result,
            "mirror_paths": mirror_paths,
            "mirror_remaining_count": len(mirror_paths),
            "mirror_centrality": mirror_centrality,
            "simulation_latency_ms": round(duration_ms, 2),
            "verified_contained": len(mirror_paths) == 0,
            "telemetry": mirror_client.last_telemetry
        }

    # --------------------------------------------------------------------------
    # Cryptographic State Hash
    # --------------------------------------------------------------------------

    def compute_graph_state_hash(self) -> str:
        """
        Computes deterministic SHA-256 integrity hash of current graph state
        (node statuses and active ATTACK_STEP edges).
        """
        nodes_res = self._execute_query(QUERY_GRAPH_NODES_STATE, read_only=True)
        edges_res = self._execute_query(QUERY_GRAPH_EDGES_STATE, read_only=True)

        canonical_data = {
            "graph_name": self.graph_name,
            "nodes": [
                {"id": r[0], "status": r[1], "cost": r[2]}
                for r in nodes_res.result_set
            ],
            "edges": [
                {"src": r[0], "dst": r[1], "active": r[2]}
                for r in edges_res.result_set
            ]
        }
        serialized = json.dumps(canonical_data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    # --------------------------------------------------------------------------
    # Interactive Stress-Testing & Topology Mutation Methods
    # --------------------------------------------------------------------------

    def list_entities(self) -> List[Dict[str, Any]]:
        """Return all entity nodes currently present in FalkorDB."""
        res = self._execute_query(QUERY_LIST_ENTITIES, read_only=True)
        entities: List[Dict[str, Any]] = []
        for record in res.result_set:
            entities.append({
                "id": record[0],
                "name": record[1],
                "kind": record[2],
                "criticality": record[3],
                "cost": int(record[4]),
                "status": record[5]
            })
        return entities

    def inject_bypass_edge(
        self,
        source_id: str,
        target_id: str,
        evidence_id: str = "E-STRESS-BYPASS"
    ) -> MutationResult:
        """
        Stress-testing control: injects an active attack edge to test counterfactual recalculations.
        """
        validate_node_id(source_id)
        validate_node_id(target_id)
        validate_node_id(evidence_id)

        params = {
            "source_id": source_id,
            "target_id": target_id,
            "evidence_id": evidence_id
        }
        res = self._execute_query(QUERY_INJECT_BYPASS_EDGE, params, read_only=False)
        created_count = int(res.result_set[0][0]) if res.result_set else 0
        return MutationResult(disabled_ids=[], updated_node_count=0, updated_edge_count=created_count)

    def remove_bypass_edge(self, evidence_id: str = "E-STRESS-BYPASS") -> MutationResult:
        """Removes the injected stress-test bypass route."""
        validate_node_id(evidence_id)
        params = {"evidence_id": evidence_id}
        res = self._execute_query(QUERY_REMOVE_BYPASS_EDGE, params, read_only=False)
        deleted_count = int(res.result_set[0][0]) if res.result_set else 0
        return MutationResult(disabled_ids=[], updated_node_count=0, updated_edge_count=deleted_count)

    def update_node_cost(self, node_id: str, new_cost: int) -> MutationResult:
        """Dynamically tweaks an entity's operational impact cost in FalkorDB and synchronizes blast radius."""
        validate_node_id(node_id)
        if not isinstance(new_cost, int) or new_cost < 0:
            raise ValueError(f"new_cost must be non-negative integer, got {new_cost}")

        params = {"node_id": node_id, "new_cost": new_cost}
        self._execute_query(QUERY_UPDATE_NODE_COST, params, read_only=False)

        # Synchronize downstream service impact scores so reverse traversal reflects new_cost
        svcs_res = self._execute_query(
            "MATCH (s:Service)-[:DEPENDS_ON*1..4]->(e:Entity {id: $node_id}) RETURN s.id AS sid",
            {"node_id": node_id},
            read_only=True
        )
        svcs = [r[0] for r in svcs_res.result_set] if svcs_res.result_set else []
        for idx, sid in enumerate(svcs):
            sc = new_cost if idx == 0 else 0
            self._execute_query(
                "MATCH (s:Service {id: $sid}) SET s.revenue_impact_score = $sc",
                {"sid": sid, "sc": sc},
                read_only=False
            )

        return MutationResult(disabled_ids=[], updated_node_count=1, updated_edge_count=0)


# ==============================================================================
# Read-Only Investigation Client (Strict Interface Segregation for LLM Tools)
# ==============================================================================

class ReadOnlyGraphClient:
    """
    Read-only wrapper around FalkorGraphClient.
    Physically prevents state mutation from LLM agent tools or unauthorized callers.
    """

    def __init__(self, client: FalkorGraphClient):
        self._client = client

    def check_connection(self) -> bool:
        return self._client.check_connection()

    @property
    def last_telemetry(self) -> Optional[QueryTelemetry]:
        return self._client.last_telemetry

    @property
    def telemetry_history(self) -> List[QueryTelemetry]:
        return self._client.telemetry_history

    def discover_attack_paths(
        self,
        source_id: str,
        target_id: Optional[str] = None,
        max_hops: int = 8
    ) -> List[AttackPath]:
        return self._client.discover_attack_paths(source_id=source_id, target_id=target_id, max_hops=max_hops)

    def get_betweenness_centrality(self) -> List[CentralityScore]:
        return self._client.get_betweenness_centrality()

    def count_remaining_paths(
        self,
        source_id: str,
        severed_ids: Optional[List[str]] = None,
        target_id: Optional[str] = None,
        max_hops: int = 8
    ) -> int:
        return self._client.count_remaining_paths(
            source_id=source_id,
            severed_ids=severed_ids,
            target_id=target_id,
            max_hops=max_hops
        )

    def compute_blast_radius(self, candidate_ids: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
        return self._client.compute_blast_radius(candidate_ids=candidate_ids)

    def compute_graph_state_hash(self) -> str:
        return self._client.compute_graph_state_hash()

    def get_cut_candidates(self, path_node_ids: List[str], source_id: str) -> List[MitigationCandidate]:
        return self._client.get_cut_candidates(path_node_ids=path_node_ids, source_id=source_id)

    def list_entities(self) -> List[Dict[str, Any]]:
        return self._client.list_entities()

    def apply_containment_action(self, blocked_ids: List[str]):
        raise PermissionError(
            "State mutation is strictly write-gated. Read-only investigative tools cannot execute containment."
        )

    def clone_to_mirror(self, mirror_graph_name: Optional[str] = None):
        raise PermissionError("State mutation is strictly write-gated. Read-only tools cannot clone graphs.")

    def simulate_mirror_containment(self, blocked_ids: List[str], **kwargs):
        raise PermissionError("State mutation is strictly write-gated. Read-only tools cannot simulate containment.")

    def inject_bypass_edge(self, source_id: str, target_id: str, evidence_id: str = "E-STRESS-BYPASS"):
        raise PermissionError("State mutation is strictly write-gated. Read-only tools cannot inject edges.")

    def remove_bypass_edge(self, evidence_id: str = "E-STRESS-BYPASS"):
        raise PermissionError("State mutation is strictly write-gated. Read-only tools cannot delete edges.")

    def update_node_cost(self, node_id: str, new_cost: int):
        raise PermissionError("State mutation is strictly write-gated. Read-only tools cannot update costs.")
