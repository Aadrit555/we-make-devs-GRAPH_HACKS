"""
logic.py — Orchestration and service layer for TEZCATL.

Coordinates between graph_client.py and cut_set_calculator.py.
Handles plan generation, multi-graph mirror sandbox verification,
cryptographic containment receipt generation, and freshness revalidation.
No UI or LLM logic belongs in this module.
"""

from datetime import datetime, timezone
import json
from typing import Optional, List, Dict, Any, Tuple
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
from solver import (
    CutPlan,
    compute_minimum_cost_cut,
)
from config import settings
from models import (
    SparedBottleneck,
    ExecutedQueryRecord,
    ContainmentAuditReceipt,
)


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
    mirror_simulation: Optional[Dict[str, Any]] = None
    pre_mitigation_hash: Optional[str] = None
    audit_receipt: Optional[ContainmentAuditReceipt] = None


class GraphFreshnessError(Exception):
    """Raised when the graph state has changed between plan calculation and approval."""
    def __init__(self, message: str):
        super().__init__(message)


# ==============================================================================
# Containment Service Layer
# ==============================================================================

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
        source_id: str = settings.tezcatl_source_id,
        target_id: str = settings.tezcatl_target_id,
        max_hops: int = 8,
        run_mirror_sim: bool = True
    ) -> IncidentAnalysisResult:
        """
        Executes end-to-end incident investigation:
        1. Validates source and target IDs with strict security regex.
        2. Discovers active directed attack paths from source_id via live FalkorDB query.
        3. Retrieves native betweenness centrality scores.
        4. Dynamically computes operational blast radius costs from FalkorDB dependencies.
        5. Calculates minimum-cost vertex cut intersecting all paths.
        6. Runs counterfactual sandbox simulation in isolated 'tezcatl_mirror' graph.
        7. Computes pre-mitigation cryptographic state hash.
        """
        validate_node_id(source_id)
        validate_node_id(target_id)

        # 0. Pre-mitigation state hash
        pre_hash = self.client.compute_graph_state_hash()

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
                telemetry=self.client.last_telemetry,
                pre_mitigation_hash=pre_hash
            )

        # 3. Collect unique nodes on paths
        all_path_node_ids = sorted(list({node_id for p in paths for node_id in p.node_ids}))

        # 4. Fetch candidate costs from FalkorDB (dynamically derived via compute_blast_radius)
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

        # 8. Counterfactual Mirror Sandbox Simulation
        mirror_sim = None
        if run_mirror_sim and plan and plan.selected_node_ids:
            try:
                mirror_sim = self.client.simulate_mirror_containment(
                    blocked_ids=plan.selected_node_ids,
                    source_id=source_id,
                    target_id=target_id,
                    max_hops=max_hops
                )
            except Exception:
                # Do not fail closed if sandbox cloning fails in constrained test environments
                mirror_sim = None

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
            telemetry=self.client.last_telemetry,
            mirror_simulation=mirror_sim,
            pre_mitigation_hash=pre_hash
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
        source_id: str = settings.tezcatl_source_id,
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

    def apply_and_audit_containment(
        self,
        source_id: str,
        target_id: str,
        expected_cut_ids: List[str],
        incident_id: str = "INC-TEZCATL-01",
        max_hops: int = 8
    ) -> Tuple[MutationResult, ContainmentAuditReceipt]:
        """
        Executes production containment mutation with end-to-end cryptographic audit:
        1. Records pre-mitigation SHA-256 graph state hash.
        2. Validates topology freshness and severs proposed cut-set.
        3. Verifies post-mitigation 0 paths in FalkorDB.
        4. Records post-mitigation SHA-256 graph state hash.
        5. Computes spared high-centrality bottlenecks.
        6. Captures live query latencies and constructs ContainmentAuditReceipt.
        """
        start_time = datetime.now(timezone.utc)
        pre_hash = self.client.compute_graph_state_hash()

        # Capture telemetry start index
        initial_history_len = len(self.client.telemetry_history)

        # 1. Fetch pre-mitigation candidates and centrality to identify spared bottlenecks
        paths = self.client.discover_attack_paths(source_id=source_id, target_id=target_id, max_hops=max_hops)
        centrality = self.client.get_betweenness_centrality()
        centrality_map = {c.id: c.score for c in centrality}
        all_path_node_ids = sorted(list({node_id for p in paths for node_id in p.node_ids}))
        candidates = self.client.get_cut_candidates(all_path_node_ids, source_id=source_id)
        candidate_map = {c.id: c for c in candidates}

        # 2. Validate freshness and apply mutation to prod_graph
        mut_res = self.validate_and_apply_plan(
            source_id=source_id,
            target_id=target_id,
            expected_cut_ids=expected_cut_ids,
            max_hops=max_hops
        )

        # 3. Post-action verification
        post_paths_count = self.verify_containment_post_action(
            source_id=source_id,
            target_id=target_id,
            max_hops=max_hops
        )

        if post_paths_count != 0:
            raise GraphFreshnessError(
                f"Containment verification failed: {post_paths_count} attack paths remain in production graph."
            )

        # 4. Post-mitigation state hash
        post_hash = self.client.compute_graph_state_hash()

        # 5. Calculate spared bottlenecks (e.g., release_controller spared while credentials severed)
        spared_bottlenecks: List[SparedBottleneck] = []
        for cand in candidates:
            if cand.id not in expected_cut_ids:
                # Include candidates that are high centrality or have services spared
                c_score = centrality_map.get(cand.id, 0.0)
                if c_score > 0.05 or cand.downstream_count > 0:
                    spared_bottlenecks.append(SparedBottleneck(
                        node_id=cand.id,
                        node_name=cand.name,
                        kind=cand.kind,
                        centrality_score=c_score,
                        blast_radius_cost=cand.cost,
                        services_preserved=cand.downstream_services
                    ))

        # 6. Extract telemetry for queries executed during this operation
        recent_telemetry = self.client.telemetry_history[initial_history_len:]
        query_records = [
            ExecutedQueryRecord(
                query=t.query,
                params=t.params,
                latency_ms=t.latency_ms
            )
            for t in recent_telemetry
        ]
        total_latency = sum(q.latency_ms for q in query_records)

        # Calculate total blast radius of selected nodes
        total_blast = sum(candidate_map[cid].cost for cid in expected_cut_ids if cid in candidate_map)
        cut_names = [candidate_map[cid].name if cid in candidate_map else cid for cid in expected_cut_ids]

        receipt = ContainmentAuditReceipt(
            incident_id=incident_id,
            timestamp_utc=start_time.isoformat(),
            source_id=source_id,
            target_id=target_id,
            optimal_cut_ids=expected_cut_ids,
            optimal_cut_names=cut_names,
            total_blast_radius_cost=total_blast,
            spared_bottlenecks=spared_bottlenecks,
            executed_queries=query_records,
            total_execution_latency_ms=round(total_latency, 4),
            pre_mitigation_graph_hash=pre_hash,
            post_mitigation_graph_hash=post_hash,
            verified_remaining_paths=0,
            verification_status="CONTAINED_AND_VERIFIED",
            verification_scope="eight_hop_bounded_reachability"
        )

        return mut_res, receipt
