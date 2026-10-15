"""
TEZCATL Sovereign Graph Engine — Authored by Aadrit555
models.py — Strongly-typed Pydantic schemas for domain entities, graph telemetry,
pipeline stages, and cryptographic receipts.
"""

import json
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class QueryTelemetry(BaseModel):
    """Direct execution telemetry recorded from FalkorDB query execution."""
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
    """Structured representation of an active directed attack trajectory."""
    model_config = ConfigDict(extra="forbid")

    node_ids: List[str]
    node_names: List[str]
    node_kinds: List[str]
    mechanisms: List[str]
    evidence_ids: List[str]
    hops: int = Field(ge=1, le=8)


class CentralityScore(BaseModel):
    """Betweenness centrality metric for a graph entity."""
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
    """Result of executing containment mutation or test topology injection."""
    model_config = ConfigDict(extra="forbid")

    disabled_ids: List[str]
    updated_node_count: int = Field(ge=0)
    updated_edge_count: int = Field(ge=0)


class InvestigationContext(BaseModel):
    """Resolved context emitted by Stage 1 Intent & Entity Resolution."""
    model_config = ConfigDict(extra="forbid")

    raw_query: str
    resolved_source_id: str
    resolved_source_name: str
    resolved_target_id: str
    resolved_target_name: str
    exclude_ids: List[str] = Field(
        default_factory=list,
        description="Operator-pinned entities protected from being severed"
    )
    max_hops: int = Field(default=8, ge=1, le=8)
    intent: str = Field(default="CONTAINMENT_DISCOVERY")


class CutPlan(BaseModel):
    """Authoritative output of Stage 3 Combinatorial Solver."""
    model_config = ConfigDict(extra="forbid")

    selected_node_ids: List[str]
    selected_node_names: List[str]
    total_cost: int = Field(ge=0, description="Sum of graph-computed blast radius costs")
    paths_evaluated_count: int = Field(ge=0)
    paths_covered_count: int = Field(ge=0)
    covered_path_indices: List[int]
    path_intersections: Dict[str, List[int]] = Field(
        default_factory=dict,
        description="Mapping from candidate node ID to 0-based indices of attack paths it intersects"
    )
    explanation: str
    scope_metadata: str = Field(
        default="minimum-cost cut over candidate nodes and paths bounded to 8 hops"
    )

    @property
    def action_ids(self) -> List[str]:
        return self.selected_node_ids


class SparedBottleneck(BaseModel):
    """Details of a high-centrality bridge entity preserved online."""
    model_config = ConfigDict(extra="forbid")

    node_id: str
    node_name: str
    kind: str
    centrality_score: float = Field(ge=0.0)
    blast_radius_cost: int = Field(ge=0)
    services_preserved: List[str]


class ExecutedQueryRecord(BaseModel):
    """Exact parameterized Cypher query executed during containment."""
    model_config = ConfigDict(extra="forbid")

    query: str
    params: Dict[str, Any]
    latency_ms: float = Field(ge=0.0)


class ContainmentAuditReceipt(BaseModel):
    """
    Cryptographic containment receipt proving counterfactual containment,
    spared bottlenecks, live Cypher execution latencies, and pre/post SHA-256 state hashes.
    """
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    timestamp_utc: str
    source_id: str
    target_id: str
    optimal_cut_ids: List[str]
    optimal_cut_names: List[str]
    total_blast_radius_cost: int = Field(ge=0)
    spared_bottlenecks: List[SparedBottleneck]
    executed_queries: List[ExecutedQueryRecord]
    total_execution_latency_ms: float = Field(ge=0.0)
    pre_mitigation_graph_hash: str
    post_mitigation_graph_hash: str
    verified_remaining_paths: int = 0
    verification_status: str = "CONTAINED_AND_VERIFIED"
    verification_scope: str = "eight_hop_bounded_reachability"

    def to_json(self, indent: int = 2) -> str:
        return self.model_dump_json(indent=indent)

    def to_markdown(self) -> str:
        lines = [
            "# TEZCATL Containment Audit Receipt",
            f"- **Incident ID:** `{self.incident_id}`",
            f"- **Timestamp (UTC):** `{self.timestamp_utc}`",
            f"- **Compromised Ingress Source:** `{self.source_id}`",
            f"- **Protected Crown-Jewel Target:** `{self.target_id}`",
            f"- **Containment Status:** `<span style='color:#3fb950;'>{self.verification_status}</span>` (`{self.verified_remaining_paths}` remaining paths)",
            f"- **Total Operational Blast Radius Cost:** `{self.total_blast_radius_cost}`",
            "",
            "## 1. Optimal Containment Plan Applied",
        ]
        for cid, cname in zip(self.optimal_cut_ids, self.optimal_cut_names):
            lines.append(f"- **Severed Entity:** `{cid}` ({cname})")

        lines.extend([
            "",
            "## 2. High-Centrality Structural Bottlenecks Spared",
        ])
        if self.spared_bottlenecks:
            for b in self.spared_bottlenecks:
                svcs = ", ".join([f"`{s}`" for s in b.services_preserved]) if b.services_preserved else "None"
                lines.append(
                    f"- **`{b.node_name}`** (`{b.node_id}`): "
                    f"Betweenness Centrality: `{b.centrality_score:.4f}` | "
                    f"Disruption Spared: `{b.blast_radius_cost}` | "
                    f"Downstream Services Preserved: {svcs}"
                )
        else:
            lines.append("- No intermediate bridge entities required preservation.")

        lines.extend([
            "",
            "## 3. Cryptographic Graph State Integrity Hashes (SHA-256)",
            f"- **Pre-Mitigation Graph State Hash:** `{self.pre_mitigation_graph_hash}`",
            f"- **Post-Mitigation Graph State Hash:** `{self.post_mitigation_graph_hash}`",
            "",
            f"## 4. FalkorDB Query Execution Telemetry (Roundtrip: `{self.total_execution_latency_ms:.2f} ms`)",
            "| Cypher Query | Parameters | FalkorDB Latency |",
            "|---|---|---|",
        ])
        for q in self.executed_queries:
            q_clean = q.query.replace("\n", " ").strip()
            if len(q_clean) > 55:
                q_clean = q_clean[:52] + "..."
            params_str = json.dumps(q.params)
            lines.append(f"| `{q_clean}` | `{params_str}` | `{q.latency_ms:.4f} ms` |")

        return "\n".join(lines)


class PipelineStageResult(BaseModel):
    """Standardized result emitted by each stage in the Tezcatl sovereign pipeline."""
    model_config = ConfigDict(extra="forbid")

    stage_name: str
    status: str
    execution_time_ms: float = Field(ge=0.0)
    cypher_queries_executed: List[str] = Field(default_factory=list)
    output_summary: str
    stage_data: Dict[str, Any] = Field(default_factory=dict)
