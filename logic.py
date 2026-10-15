"""
logic.py — Orchestration and service layer for CUTLINE v2.

Coordinates between graph_client.py and cut_set_calculator.py.
Handles plan generation, freshness revalidation, and containment orchestration.
No UI or LLM logic belongs in this module.
"""

from typing import Optional, List, Dict
from pydantic import BaseModel, ConfigDict, Field

from graph_client import (
    FalkorGraphClient,
    AttackPath,
    CentralityScore,
    MitigationCandidate,
    MutationResult,
    QueryTelemetry,
    validate_node_id,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_GRAPH,
)
from cut_set_calculator import (
    CutPlan,
    compute_minimum_cost_cut,
)
from config import settings


class IncidentAnalysisResult(BaseModel):
    """Complete structured output of the graph investigation and optimization workflow."""
    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    target_id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    discovered_paths: List[AttackPath]
    centrality_scores: List[CentralityScore]
    eligible_candidates: List[MitigationCandidate]
    recommended_plan: Optional[CutPlan] = None
    counterfactual_remaining_paths: int = Field(ge=0)
    graph_is_contained: bool
    status_message: str
    telemetry: Optional[QueryTelemetry] = None


class GraphFreshnessError(Exception):
    """Raised when the graph state has changed between plan calculation and approval."""
    def __init__(self, message: str):
        super().__init__(message)


class ContainmentService:
    """Service layer orchestrating live graph analysis, cut calculation, and containment."""

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        graph_name: str = DEFAULT_GRAPH,
        client: Optional[FalkorGraphClient] = None
    ):
        self.client = client or FalkorGraphClient(host=host, port=port, graph_name=graph_name)

    def analyze_incident(
        self,
        source_id: str = settings.cutline_source_id,
        target_id: str = settings.cutline_target_id,
        max_hops: int = 8
    ) -> IncidentAnalysisResult:
        """
        Executes end-to-end incident investigation:
        1. Validates source and target IDs with strict security regex.
        2. Discovers active directed attack paths from source_id via live FalkorDB query.
        3. Retrieves native betweenness centrality scores.
        4. Fetches candidate entities and synthetic costs from FalkorDB.
        5. Calculates minimum-cost vertex cut intersecting all paths.
        6. Computes counterfactual remaining path count.
        """
        validate_node_id(source_id)
        validate_node_id(target_id)

        # 1. Discover paths (fails closed with typed exception if FalkorDB fails)
        paths = self.client.discover_attack_paths(source_id=source_id, target_id=target_id, max_hops=max_hops)

        # 2. Fetch centrality
        centrality = self.client.get_betweenness_centrality()

        # If no active paths exist, system is already contained
        if not paths:
            return IncidentAnalysisResult(
                source_id=source_id,
                target_id=target_id,
                discovered_paths=[],
                centrality_scores=centrality,
                eligible_candidates=[],
                recommended_plan=None,
                counterfactual_remaining_paths=0,
                graph_is_contained=True,
                status_message="Zero active attack paths detected. The asset is already contained.",
                telemetry=self.client.last_telemetry
            )

        # 3. Collect unique nodes on paths
        all_path_node_ids = sorted(list({node_id for p in paths for node_id in p.node_ids}))

        # 4. Fetch candidate costs from FalkorDB
        candidates = self.client.get_cut_candidates(all_path_node_ids, source_id=source_id)

        candidate_costs: Dict[str, int] = {c.id: c.cost for c in candidates}
        candidate_names: Dict[str, str] = {c.id: c.name for c in candidates}

        # 5. Extract path node ID sequences
        path_node_sequences = [p.node_ids for p in paths]

        # 6. Run pure deterministic optimizer
        plan = compute_minimum_cost_cut(
            attack_paths=path_node_sequences,
            candidate_costs=candidate_costs,
            candidate_names=candidate_names,
            source_id=source_id,
            crown_jewel_ids={target_id}
        )

        # 7. Pre-action counterfactual verification check
        remaining_paths = self.client.count_remaining_paths(
            source_id=source_id,
            severed_ids=plan.selected_node_ids,
            target_id=target_id,
            max_hops=max_hops
        )

        return IncidentAnalysisResult(
            source_id=source_id,
            target_id=target_id,
            discovered_paths=paths,
            centrality_scores=centrality,
            eligible_candidates=candidates,
            recommended_plan=plan,
            counterfactual_remaining_paths=remaining_paths,
            graph_is_contained=False,
            status_message=f"Discovered {len(paths)} attack paths. Minimum-cost cut requires {len(plan.selected_node_ids)} actions at modeled cost {plan.total_cost}.",
            telemetry=self.client.last_telemetry
        )

    def validate_and_apply_plan(
        self,
        source_id: str,
        target_id: str,
        expected_cut_ids: List[str],
        max_hops: int = 8
    ) -> MutationResult:
        """
        Revalidates graph freshness before executing state mutation.
        Refuses to apply if the current graph topology has changed or if
        the proposed action does not fully sever all active paths.
        """
        validate_node_id(source_id)
        validate_node_id(target_id)
        for cid in expected_cut_ids:
            validate_node_id(cid)

        # Re-check active paths currently in the database
        fresh_paths = self.client.discover_attack_paths(source_id=source_id, target_id=target_id, max_hops=max_hops)
        if not fresh_paths:
            raise GraphFreshnessError("Graph state has changed: no active attack paths exist currently.")

        # Re-check that proposed cut leaves exactly 0 paths
        predicted_remaining = self.client.count_remaining_paths(
            source_id=source_id,
            severed_ids=expected_cut_ids,
            target_id=target_id,
            max_hops=max_hops
        )

        if predicted_remaining != 0:
            raise GraphFreshnessError(
                f"Freshness check failed: proposed cut {expected_cut_ids} leaves {predicted_remaining} active paths."
            )

        # Apply mutation (gated execution)
        mutation_result = self.client.apply_containment_action(expected_cut_ids)
        return mutation_result

    def verify_containment_post_action(
        self,
        source_id: str = settings.cutline_source_id,
        target_id: Optional[str] = None,
        max_hops: int = 8
    ) -> int:
        """
        Runs fresh post-action query against FalkorDB after mutation.
        Supplies severed_ids = [] because the nodes are now marked 'disabled'
        and attack relationships are active = false.
        """
        validate_node_id(source_id)
        if target_id is not None:
            validate_node_id(target_id)

        remaining = self.client.count_remaining_paths(
            source_id=source_id,
            severed_ids=[],
            target_id=target_id,
            max_hops=max_hops
        )
        return remaining
