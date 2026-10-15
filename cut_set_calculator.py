"""
cut_set_calculator.py — Pure, deterministic minimum-cost vertex-cut engine for TEZCATL.

This module contains pure combinatorial mathematics.
It has NO database connection, NO FalkorDB client dependency,
NO Streamlit imports, and NO LLM calls.
All Pydantic models are strictly validated with extra='forbid'.
"""

from typing import List, Set, Dict, Optional, Tuple
from itertools import combinations
from pydantic import BaseModel, Field, ConfigDict

# Maximum allowed candidate nodes for exhaustive evaluation (2^18 - 1 = 262,143 combinations)
MAX_CANDIDATE_CAP = 18


class CutPlan(BaseModel):
    """Authoritative output of the minimum-cost cut-set calculation."""
    model_config = ConfigDict(extra="forbid")

    selected_node_ids: List[str]
    selected_node_names: List[str]
    total_cost: int = Field(ge=0, description="Sum of modeled costs of selected mitigation entities")
    paths_evaluated_count: int = Field(ge=0)
    paths_covered_count: int = Field(ge=0)
    covered_path_indices: List[int]
    path_intersections: Dict[str, List[int]] = Field(
        default_factory=dict,
        description="Mapping from candidate node ID to the 0-based indices of attack paths it intersects"
    )
    explanation: str
    scope_metadata: str = Field(
        default="minimum-cost cut over the available candidate nodes and paths returned by the current query, bounded to eight hops."
    )

    @property
    def action_ids(self) -> List[str]:
        """Convenience property matching test expectations."""
        return self.selected_node_ids


class NoValidCutError(Exception):
    """Raised when no combination of available candidates severs all attack paths."""
    def __init__(self, message: str):
        super().__init__(message)


class CandidateCapExceededError(Exception):
    """Raised when candidate count exceeds the exhaustive search safety cap."""
    def __init__(self, message: str):
        super().__init__(message)


class InvalidCandidateDataError(ValueError):
    """Raised when input candidate data violates domain invariants."""
    def __init__(self, message: str):
        super().__init__(message)


def compute_minimum_cost_cut(
    attack_paths: List[List[str]],
    candidate_costs: Dict[str, int],
    candidate_names: Optional[Dict[str, str]] = None,
    source_id: Optional[str] = None,
    crown_jewel_ids: Optional[Set[str]] = None,
    max_candidate_cap: int = MAX_CANDIDATE_CAP,
) -> CutPlan:
    """
    Computes the lowest-cost vertex cut intersecting every path in attack_paths.

    Args:
        attack_paths: List of paths, each path being an ordered list of node IDs.
        candidate_costs: Dict mapping candidate node ID to non-negative integer cost.
        candidate_names: Optional dict mapping candidate node ID to human-readable name.
        source_id: Node ID of the incident source (protected from selection).
        crown_jewel_ids: Set of target crown-jewel node IDs (protected from selection).
        max_candidate_cap: Maximum number of distinct candidates allowed.

    Returns:
        CutPlan containing selected nodes, total cost, and path coverage details.

    Raises:
        InvalidCandidateDataError: if costs are negative, paths are malformed, or candidates are invalid.
        CandidateCapExceededError: if distinct candidate count exceeds max_candidate_cap.
        NoValidCutError: if no subset of candidates severs all paths.
    """
    if candidate_names is None:
        candidate_names = {}
    if crown_jewel_ids is None:
        crown_jewel_ids = set()

    # 1. Edge Case: No attack paths to sever
    if not attack_paths or len(attack_paths) == 0:
        return CutPlan(
            selected_node_ids=[],
            selected_node_names=[],
            total_cost=0,
            paths_evaluated_count=0,
            paths_covered_count=0,
            covered_path_indices=[],
            path_intersections={},
            explanation="No active attack paths present to contain."
        )

    # 2. Validate paths & normalize to sets for fast intersection testing
    normalized_path_sets: List[Set[str]] = []
    for idx, p in enumerate(attack_paths):
        if not p or len(p) < 2:
            raise InvalidCandidateDataError(f"Path at index {idx} is malformed (has fewer than 2 nodes): {p}")
        normalized_path_sets.append(set(p))

    # 3. Validate candidate costs
    for node_id, cost in candidate_costs.items():
        if not isinstance(cost, int) or cost < 0:
            raise InvalidCandidateDataError(f"Candidate '{node_id}' has invalid cost: {cost}. Cost must be non-negative integer.")

    # 4. Filter eligible candidates: must appear on at least one path, and NOT be source or crown jewel
    all_path_nodes = set().union(*normalized_path_sets)
    protected_nodes = set()
    if source_id:
        protected_nodes.add(source_id)
    protected_nodes.update(crown_jewel_ids)

    eligible_candidates: List[str] = []
    for node_id in sorted(candidate_costs.keys()):
        if node_id in protected_nodes:
            continue
        if node_id in all_path_nodes:
            eligible_candidates.append(node_id)

    # 5. Enforce candidate cap
    if len(eligible_candidates) > max_candidate_cap:
        raise CandidateCapExceededError(
            f"Eligible candidate count ({len(eligible_candidates)}) exceeds safety cap ({max_candidate_cap}). "
            f"Exhaustive search refused to prevent exponential explosion."
        )

    # 6. Precompute candidate -> path intersections
    node_to_path_indices: Dict[str, Set[int]] = {cand: set() for cand in eligible_candidates}
    for p_idx, p_set in enumerate(normalized_path_sets):
        for cand in eligible_candidates:
            if cand in p_set:
                node_to_path_indices[cand].add(p_idx)

    total_paths = len(normalized_path_sets)
    all_path_indices = set(range(total_paths))

    # 7. Combinatorial search for minimum-cost vertex cut
    valid_cuts: List[Tuple[int, int, Tuple[str, ...]]] = []

    for r in range(1, len(eligible_candidates) + 1):
        for combo in combinations(eligible_candidates, r):
            covered_indices: Set[int] = set()
            for cand in combo:
                covered_indices.update(node_to_path_indices[cand])

            if covered_indices == all_path_indices:
                cost = sum(candidate_costs[cand] for cand in combo)
                sorted_combo = tuple(sorted(combo))
                valid_cuts.append((cost, len(combo), sorted_combo))

    # 8. Check if any valid cut exists
    if not valid_cuts:
        raise NoValidCutError(
            f"No valid cut found among {len(eligible_candidates)} eligible candidates to sever all {total_paths} paths."
        )

    # 9. Deterministic tie-breaking: minimum cost, then smallest cardinality, then lexicographical order
    valid_cuts.sort(key=lambda item: (item[0], item[1], item[2]))
    best_cost, best_count, best_tuple = valid_cuts[0]
    selected_ids = list(best_tuple)

    # 10. Assemble structured output
    selected_names = [candidate_names.get(cid, cid) for cid in selected_ids]
    path_intersections = {cid: sorted(list(node_to_path_indices[cid])) for cid in selected_ids}

    explanation_parts = [
        f"Selected minimum-cost cut: {', '.join(selected_ids)}.",
        f"Total modeled operational impact cost: {best_cost}.",
        f"Fully severs {total_paths} of {total_paths} active attack paths."
    ]

    return CutPlan(
        selected_node_ids=selected_ids,
        selected_node_names=selected_names,
        total_cost=best_cost,
        paths_evaluated_count=total_paths,
        paths_covered_count=total_paths,
        covered_path_indices=sorted(list(all_path_indices)),
        path_intersections=path_intersections,
        explanation=" ".join(explanation_parts)
    )
