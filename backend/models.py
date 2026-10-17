"""
TEZCATL — Pydantic Validation & Domain Models
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""
from typing import Any, List, Optional, Dict, Set
from pydantic import BaseModel, Field, field_validator, model_validator
from backend.config import (
    MAX_NODE_COUNT,
    MAX_EDGE_COUNT,
    MAX_TRAVERSAL_DEPTH,
    MAX_CANDIDATES,
)

# Canonical allowlist of supported relationship semantics
ALLOWED_RELATIONSHIP_TYPES: Set[str] = {
    "CALLS",
    "DEPENDS_ON",
    "READS_FROM",
    "WRITES_TO",
    "ASSUMES_ROLE",
    "DEPLOYS_TO",
    "ATTACK_STEP",
}


# ==============================================================================
# 1. CANONICAL MANIFEST MODELS (Phase Three & Four)
# ==============================================================================

class ProjectInfo(BaseModel):
    id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]{1,64}$", description="Normalized project ID")
    name: str = Field(..., min_length=1, max_length=128, description="Display project name")


class ManifestNode(BaseModel):
    id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]{1,64}$", description="Unique entity/node ID")
    name: str = Field(..., min_length=1, max_length=128, description="Human-readable node label")
    kind: str = Field(..., description="Node categorization: service, application, database, credential, role")
    criticality: str = Field(default="medium", description="Criticality level: low, medium, high, crown_jewel")
    status: str = Field(default="active", description="Node lifecycle status: active, isolated, severed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary validated metadata")


class ManifestEdge(BaseModel):
    id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]{1,64}$", description="Unique edge identifier")
    source: str = Field(..., description="Source node ID")
    target: str = Field(..., description="Target node ID")
    type: str = Field(..., description="Relationship type from canonical allowlist")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary edge metadata")

    @field_validator("type")
    @classmethod
    def validate_relationship_type(cls, v: str) -> str:
        if v not in ALLOWED_RELATIONSHIP_TYPES:
            raise ValueError(
                f"Relationship type '{v}' is not supported. "
                f"Allowed types: {sorted(ALLOWED_RELATIONSHIP_TYPES)}"
            )
        return v


class EligibleMitigation(BaseModel):
    node_id: str = Field(..., description="Node eligible for isolation")
    blast_cost: int = Field(..., ge=0, description="Modeled business or service disruption cost")
    impact_justification: str = Field(default="", description="Provenance or rationale for the cost")
    impacted_services: List[str] = Field(default_factory=list, description="Downstream services affected")


class SecurityScenario(BaseModel):
    source_id: str = Field(..., description="Breach origin ID")
    target_ids: List[str] = Field(default_factory=list, description="Target crown jewel asset IDs")
    allowed_traversal_types: List[str] = Field(
        default_factory=lambda: ["ATTACK_STEP"],
        description="Relationship types the attacker can traverse",
    )
    max_depth: int = Field(default=8, ge=1, le=MAX_TRAVERSAL_DEPTH, description="Maximum traversal search depth")
    eligible_mitigations: List[EligibleMitigation] = Field(
        default_factory=list, description="Modeled mitigations and costs"
    )
    protected_nodes: List[str] = Field(default_factory=list, description="Nodes that cannot be cut")
    description: Optional[str] = Field(default=None, description="Scenario assumptions and notes")

    @field_validator("allowed_traversal_types")
    @classmethod
    def validate_traversal_types(cls, v: List[str]) -> List[str]:
        for t in v:
            if t not in ALLOWED_RELATIONSHIP_TYPES:
                raise ValueError(f"Traversal type '{t}' is not in allowlist {sorted(ALLOWED_RELATIONSHIP_TYPES)}")
        return v


class SecurityTopologyManifest(BaseModel):
    schema_version: int = Field(default=1, ge=1, le=1, description="Manifest schema version")
    project: ProjectInfo
    nodes: List[ManifestNode] = Field(..., min_length=1, max_length=MAX_NODE_COUNT)
    edges: List[ManifestEdge] = Field(default_factory=list, max_length=MAX_EDGE_COUNT)
    scenario: Optional[SecurityScenario] = None

    @model_validator(mode="after")
    def validate_topology_integrity(self) -> "SecurityTopologyManifest":
        node_ids = set()
        for n in self.nodes:
            if n.id in node_ids:
                raise ValueError(f"Duplicate node ID detected: '{n.id}'")
            node_ids.add(n.id)

        edge_ids = set()
        for e in self.edges:
            if e.id in edge_ids:
                raise ValueError(f"Duplicate edge ID detected: '{e.id}'")
            edge_ids.add(e.id)
            if e.source not in node_ids:
                raise ValueError(f"Edge '{e.id}' references undefined source '{e.source}'")
            if e.target not in node_ids:
                raise ValueError(f"Edge '{e.id}' references undefined target '{e.target}'")

        if self.scenario:
            sc = self.scenario
            if sc.source_id not in node_ids:
                raise ValueError(f"Scenario source '{sc.source_id}' does not exist in manifest nodes")
            for tid in sc.target_ids:
                if tid not in node_ids:
                    raise ValueError(f"Scenario target '{tid}' does not exist in manifest nodes")
            for prot in sc.protected_nodes:
                if prot not in node_ids:
                    raise ValueError(f"Protected node '{prot}' does not exist in manifest nodes")
            for em in sc.eligible_mitigations:
                if em.node_id not in node_ids:
                    raise ValueError(f"Eligible mitigation node '{em.node_id}' does not exist in manifest nodes")

        return self


# ==============================================================================
# 2. RUNTIME GRAPH & CONTAINMENT MODELS
# ==============================================================================

class CutActionRequest(BaseModel):
    """Payload for committing minimum vertex cut containment."""
    source_id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]{1,64}$", description="Breach origin ID")
    cut_nodes: List[str] = Field(..., min_length=1, description="Nodes to isolate")
    blast_cost: int = Field(default=0, ge=0, description="Calculated service disruption cost")
    scenario_id: str = Field(default="cicd-compromise", description="Target scenario identifier")
    plan_fingerprint: Optional[str] = Field(default=None, description="Cryptographic fingerprint of plan being authorized")


class PrepareMirrorRequest(BaseModel):
    """Payload for explicitly cloning and modeling containment in shadow mirror graph."""
    source_id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]{1,64}$", description="Breach origin ID")
    cut_nodes: List[str] = Field(..., min_length=1, description="Nodes to isolate in mirror")
    scenario_id: str = Field(default="cicd-compromise", description="Target scenario identifier")


class SourceRequest(BaseModel):
    """Payload for source-targeted actions such as bypass injection."""
    source_id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]{1,64}$", description="Entity ID to evaluate")
    scenario_id: str = Field(default="cicd-compromise", description="Target scenario identifier")


class TopologyNode(BaseModel):
    id: str
    name: str
    kind: str
    criticality: str
    status: str


class TopologyEdge(BaseModel):
    source: str
    target: str
    type: str = "ATTACK_STEP"
    mechanism: Optional[str] = None
    evidence_id: Optional[str] = None
    active: bool = True


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
    centrality: Optional[float] = None
    centrality_source: Optional[str] = None


class CutPlan(BaseModel):
    cut_nodes: List[str]
    cut_names: List[str]
    blast_cost: int
    paths_severed: int
    total_paths: int
    complete_cut: bool
    impacted_services: List[str]
    proximity: Optional[float] = None
    plan_fingerprint: Optional[str] = None


class CutSolution(BaseModel):
    optimal: Optional[CutPlan] = None
    evaluated: List[CutPlan] = Field(default_factory=list)
    plan_fingerprint: Optional[str] = None
    infeasible: bool = False


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


class ScenarioSummary(BaseModel):
    id: str
    name: str
    description: str
    graph_name: str
    mirror_name: str
    source_id: str
    target_ids: List[str]
    has_threat_model: bool
    threat_model_message: Optional[str] = None
    node_count: int
    edge_count: int


class InvestigationStateResponse(BaseModel):
    scenario_id: str = "cicd-compromise"
    scenario_name: str = "CI/CD Pipeline Compromise"
    graph_name: str = "prod_graph"
    source_id: str
    target_ids: List[str] = Field(default_factory=list)
    has_threat_model: bool = True
    threat_model_message: Optional[str] = None
    topology: FullTopology
    active_path_count: int
    paths: List[AttackPath]
    candidates: List[MitigationCandidate]
    cut_solution: CutSolution
    mirror_proof: Optional[MirrorProof] = None
    telemetry: List[Dict[str, Any]] = Field(default_factory=list)
