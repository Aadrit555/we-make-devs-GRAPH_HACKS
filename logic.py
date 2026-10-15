"""
logic.py — Orchestration and service layer for CUTLINE v2.

Coordinates between graph_client.py and cut_set_calculator.py.
Handles plan generation, freshness revalidation, and containment orchestration.
No UI or LLM logic belongs in this module.
"""

from typing import Optional, List, Dict, Set
from pydantic import BaseModel, Field

from graph_client import (
    FalkorGraphClient,
    AttackPath,
    CentralityScore,
    MitigationCandidate,
    MutationResult,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_GRAPH,
)
from cut_set_calculator import (
    CutPlan,
    compute_minimum_cost_cut,
    NoValidCutError,
    CandidateCapExceededError,
)


class IncidentAnalysisResult(BaseModel):
    """Complete structured output of the graph investigation and optimization workflow."""
    source_id: str
    target_id: str
    discovered_paths: List[AttackPath]
    centrality_scores: List[CentralityScore]
    eligible_candidates: List[MitigationCandidate]
    recommended_plan: Optional[CutPlan] = None
    counterfactual_remaining_paths: int
    graph_is_contained: bool
    status_message: str


class GraphFreshnessError(Exception):
    """Raised when the graph state has changed between plan calculation and approval."""
    pass


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
        source_id: str = "ci_runner",
        target_id: str = "signing_key",
        max_hops: int = 8
    ) -> IncidentAnalysisResult:
        """
        Executes end-to-end incident investigation:
        1. Discovers active directed attack paths from source_id.
        2. Retrieves native betweenness centrality scores.
        3. Fetches candidate entities and synthetic costs from FalkorDB.
        4. Calculates minimum-cost vertex cut intersecting all paths.
        5. Computes counterfactual remaining path count.
        """
        # 1. Discover paths (fails closed if FalkorDB fails)
        paths = self.client.discover_attack_paths(source_id=source_id, max_hops=max_hops)

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
                status_message="Zero active attack paths detected. The asset is already contained."
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
            status_message=f"Discovered {len(paths)} attack paths. Minimum-cost cut requires {len(plan.selected_node_ids)} actions at modeled cost {plan.total_cost}."
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
        # Re-check active paths currently in the database
        fresh_paths = self.client.discover_attack_paths(source_id=source_id, max_hops=max_hops)
        if not fresh_paths:
            raise GraphFreshnessError("Graph state has changed: no active attack paths exist currently.")

        # Re-check that proposed cut leaves exactly 0 paths
        predicted_remaining = self.client.count_remaining_paths(
            source_id=source_id,
            severed_ids=expected_cut_ids,
            max_hops=max_hops
        )

        if predicted_remaining != 0:
            raise GraphFreshnessError(
                f"Freshness check failed: proposed cut {expected_cut_ids} leaves {predicted_remaining} active paths."
            )

        # Apply mutation
        mutation_result = self.client.apply_containment_action(expected_cut_ids)
        return mutation_result

    def verify_containment_post_action(
        self,
        source_id: str = "ci_runner",
        max_hops: int = 8
    ) -> int:
        """
        Runs fresh post-action query against FalkorDB after mutation.
        Supplies severed_ids = [] because the nodes are now marked 'disabled'
        and attack relationships are active = false.
        """
        remaining = self.client.count_remaining_paths(
            source_id=source_id,
            severed_ids=[],
            max_hops=max_hops
        )
        return remaining

