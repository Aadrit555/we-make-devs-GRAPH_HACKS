"""
TEZCATL — Pydantic Validation & Domain Models
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""
from typing import Any, List, Optional, Dict
from pydantic import BaseModel, Field


class CutActionRequest(BaseModel):
    """Payload for committing minimum vertex cut containment."""
    source_id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]{1,64}$", description="Breach origin ID")
    cut_nodes: List[str] = Field(..., min_length=1, description="Nodes to isolate")
    blast_cost: int = Field(default=0, ge=0, description="Calculated service disruption cost")


class SourceRequest(BaseModel):
    """Payload for source-targeted actions such as bypass injection."""
    source_id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]{1,64}$", description="Entity ID to evaluate")


class TopologyNode(BaseModel):
    id: str
    name: str
    kind: str
    criticality: str
    status: str


class TopologyEdge(BaseModel):
    source: str
    target: str
    mechanism: str
    evidence_id: str


class FullTopology(BaseModel):
    nodes: List[TopologyNode]
    edges: List[TopologyEdge]


class AttackPath(BaseModel):
    path_id: str
    target_id: str
    hops: int
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]


class MitigationCandidate(BaseModel):
    id: str
    name: str
    kind: str
    status: str
    blast_cost: int
    impacted_services: List[str]
    centrality: float


class CutPlan(BaseModel):
    cut_nodes: List[str]
    cut_names: List[str]
    blast_cost: int
    paths_severed: int
    total_paths: int
    complete_cut: bool
    impacted_services: List[str]
    proximity: Optional[float] = None


class CutSolution(BaseModel):
    optimal: Optional[CutPlan] = None
    evaluated: List[CutPlan] = Field(default_factory=list)


class MirrorProof(BaseModel):
    mirror_graph: str
    isolated_nodes: List[str]
    remaining_paths: int
    verified_safe: bool
    telemetry: List[Dict[str, Any]] = Field(default_factory=list)


class TelemetryRecord(BaseModel):
    graph: str
    cypher: str
    params: Dict[str, Any]
    execution_ms: float
    rows: int


class ContainmentReceipt(BaseModel):
    source_id: str
    severed_nodes: List[str]
    pre_paths: int
    post_paths: int
    blast_cost: int
    timestamp: int
    sha256_receipt: str
    telemetry: List[Dict[str, Any]] = Field(default_factory=list)


class InvestigationStateResponse(BaseModel):
    source_id: str
    topology: FullTopology
    active_path_count: int
    paths: List[AttackPath]
    candidates: List[MitigationCandidate]
    cut_solution: CutSolution
    mirror_proof: Optional[MirrorProof] = None
    telemetry: List[Dict[str, Any]] = Field(default_factory=list)
