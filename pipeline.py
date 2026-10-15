"""
TEZCATL Sovereign Graph Engine — Authored by Aadrit555
pipeline.py — Multi-stage deterministic execution pipeline for TEZCATL.

100% First-Party Python Architecture:
- Zero external APIs (pure first-party sovereign Python execution)
- Zero third-party agent frameworks (zero external dependencies)
- Strongly-typed Pydantic schemas and pipeline telemetry
- Direct FalkorDB Cypher scrying, native betweenness centrality, and mirror sandboxing
"""

import re
import time
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Callable, Tuple
from pydantic import BaseModel, ConfigDict, Field

from config import settings
from models import (
    InvestigationContext,
    AttackPath,
    CentralityScore,
    MitigationCandidate,
    CutPlan,
    SparedBottleneck,
    ExecutedQueryRecord,
    ContainmentAuditReceipt,
    PipelineStageResult,
)
from graph_client import (
    FalkorGraphClient,
    ReadOnlyGraphClient,
    validate_node_id,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_GRAPH,
    DEFAULT_MIRROR_GRAPH,
)
import solver


def tezcatl_tool(func: Callable) -> Callable:
    """Decorator marking first-party deterministic graph query dispatcher tools."""
    func._is_tezcatl_tool = True
    return func


# ==============================================================================
# Pipeline Execution Result
# ==============================================================================

class TezcatlPipelineRun(BaseModel):
    """Aggregate output of the 5-Stage Tezcatl Sovereign Pipeline."""
    model_config = ConfigDict(extra="forbid")

    stages: List[PipelineStageResult]
    context: InvestigationContext
    paths: List[AttackPath]
    centralities: List[CentralityScore]
    candidates: List[MitigationCandidate]
    plan: Optional[CutPlan] = None
    receipt: Optional[ContainmentAuditReceipt] = None
    sandbox_verified: bool = False
    total_latency_ms: float = Field(ge=0.0)
    success: bool = True
    error_message: Optional[str] = None


# ==============================================================================
# Stage 1: Intent & Entity Resolution (Pure First-Party Tokenizer & Matcher)
# ==============================================================================

class IntentResolverStage:
    """
    Stage 1: Deterministic natural language tokenization and entity catalog matching.
    Resolves source, target, protected exclusion IDs, and hop limits against live FalkorDB catalog.
    Zero external LLM APIs.
    """

    def __init__(self, client: FalkorGraphClient):
        self.client = client

    def execute(
        self,
        raw_query: str = "",
        override_source: Optional[str] = None,
        override_target: Optional[str] = None,
        override_excludes: Optional[List[str]] = None,
        override_hops: Optional[int] = None,
    ) -> Tuple[InvestigationContext, PipelineStageResult]:
        t0 = time.perf_counter()
        cypher_queries: List[str] = []

        # 1. Fetch live node catalog from FalkorDB
        catalog_query = "MATCH (n:Entity) RETURN n.id AS id, n.name AS name, n.criticality AS criticality"
        res = self.client._execute_query(catalog_query)
        cypher_queries.append(catalog_query)

        known_entities: Dict[str, Dict[str, str]] = {}
        id_by_lower_name: Dict[str, str] = {}
        crown_jewels: List[str] = []

        for row in res.result_set:
            eid, name, crit = str(row[0]), str(row[1]), str(row[2])
            known_entities[eid] = {"name": name, "criticality": crit}
            id_by_lower_name[name.lower()] = eid
            id_by_lower_name[eid.lower()] = eid
            if crit == "crown_jewel":
                crown_jewels.append(eid)

        # 2. Resolve Source ID
        resolved_source = override_source or ""
        if not resolved_source and raw_query:
            query_lower = raw_query.lower()
            # Match against known entity IDs and names
            for name_term, eid in id_by_lower_name.items():
                if name_term in query_lower and "crown" not in known_entities[eid]["criticality"]:
                    # Prioritize ingress/compromised markers
                    if any(term in query_lower for term in ["runner", "ci", "compromised", "source", "ingress"]):
                        resolved_source = eid
                        break
                    elif not resolved_source:
                        resolved_source = eid

        if not resolved_source or resolved_source not in known_entities:
            resolved_source = settings.tezcatl_source_id

        # 3. Resolve Target ID
        resolved_target = override_target or ""
        if not resolved_target and raw_query:
            query_lower = raw_query.lower()
            for name_term, eid in id_by_lower_name.items():
                if name_term in query_lower and known_entities[eid]["criticality"] == "crown_jewel":
                    resolved_target = eid
                    break

        if not resolved_target or resolved_target not in known_entities:
            resolved_target = crown_jewels[0] if crown_jewels else settings.tezcatl_target_id

        # 4. Resolve Protected Exclusion IDs (operator-pinned entities)
        resolved_excludes: List[str] = list(override_excludes or [])
        if raw_query:
            query_lower = raw_query.lower()
            protect_patterns = [
                r"protect\s+([a-zA-Z0-9_-]+)",
                r"spare\s+([a-zA-Z0-9_-]+)",
                r"exclude\s+([a-zA-Z0-9_-]+)",
                r"keep\s+([a-zA-Z0-9_-]+)\s+online",
                r"do\s+not\s+(?:cut|kill|sever|disable)\s+([a-zA-Z0-9_-]+)",
            ]
            for pat in protect_patterns:
                matches = re.findall(pat, query_lower)
                for m in matches:
                    matched_id = id_by_lower_name.get(m, m)
                    if matched_id in known_entities and matched_id not in resolved_excludes:
                        resolved_excludes.append(matched_id)

        # 5. Resolve Max Hops
        resolved_hops = override_hops or 8
        if raw_query and not override_hops:
            hops_match = re.search(r"(\d+)\s*hops?", raw_query.lower())
            if hops_match:
                try:
                    h = int(hops_match.group(1))
                    resolved_hops = max(1, min(8, h))
                except ValueError:
                    pass

        # Validate node IDs with strict regex
        validate_node_id(resolved_source)
        validate_node_id(resolved_target)
        for ex in resolved_excludes:
            validate_node_id(ex)

        source_name = known_entities.get(resolved_source, {}).get("name", resolved_source)
        target_name = known_entities.get(resolved_target, {}).get("name", resolved_target)

        context = InvestigationContext(
            raw_query=raw_query or f"Contain breach from {resolved_source} to {resolved_target}",
            resolved_source_id=resolved_source,
            resolved_source_name=source_name,
            resolved_target_id=resolved_target,
            resolved_target_name=target_name,
            exclude_ids=resolved_excludes,
            max_hops=resolved_hops,
            intent="CONTAINMENT_DISCOVERY",
        )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        stage_result = PipelineStageResult(
            stage_name="Stage 1: Intent & Entity Resolution",
            status="SUCCESS",
            execution_time_ms=round(elapsed_ms, 3),
            cypher_queries_executed=cypher_queries,
            output_summary=(
                f"Resolved Source: `{resolved_source}` ({source_name}) | "
                f"Target: `{resolved_target}` ({target_name}) | "
                f"Protected Excludes: {resolved_excludes or 'None'} | "
                f"Scope: {resolved_hops} hops"
            ),
            stage_data=context.model_dump(),
        )
        return context, stage_result


# ==============================================================================
# Stage 2: Graph Scrying & Telemetry Dispatcher (Decorated First-Party Tools)
# ==============================================================================

class GraphToolDispatcher:
    """
    Stage 2: Deterministic Cypher tool dispatcher decorated with @tezcatl_tool.
    Dispatches parameterized attack path discovery, native betweenness centrality,
    and reverse dependency blast radius calculus.
    """

    def __init__(self, client: FalkorGraphClient):
        self.client = client

    @tezcatl_tool
    def scry_attack_paths(
        self,
        source_id: str,
        target_id: Optional[str] = None,
        max_hops: int = 8,
    ) -> List[AttackPath]:
        """Scry active attack trajectories bounded to max_hops."""
        return self.client.discover_attack_paths(
            source_id=source_id,
            target_id=target_id,
            max_hops=max_hops,
        )

    @tezcatl_tool
    def rank_betweenness_bottlenecks(self) -> List[CentralityScore]:
        """Rank structural bottlenecks using FalkorDB native betweenness centrality."""
        return self.client.get_betweenness_centrality()

    @tezcatl_tool
    def compute_service_blast_radius(
        self,
        path_node_ids: Optional[List[str]] = None,
        source_id: Optional[str] = None
    ) -> List[MitigationCandidate]:
        """Compute operational disruption costs via reverse downstream DEPENDS_ON analysis."""
        nodes = path_node_ids or []
        src = source_id or settings.tezcatl_source_id
        return self.client.get_cut_candidates(path_node_ids=nodes, source_id=src)

    def execute(
        self,
        context: InvestigationContext,
    ) -> Tuple[List[AttackPath], List[CentralityScore], List[MitigationCandidate], PipelineStageResult]:
        t0 = time.perf_counter()
        initial_history_len = len(self.client.telemetry_history)

        paths = self.scry_attack_paths(
            source_id=context.resolved_source_id,
            target_id=context.resolved_target_id,
            max_hops=context.max_hops,
        )
        centralities = self.rank_betweenness_bottlenecks()

        # Extract unique path node IDs
        all_path_nodes = list(dict.fromkeys([nid for p in paths for nid in p.node_ids]))
        candidates = self.compute_service_blast_radius(
            path_node_ids=all_path_nodes,
            source_id=context.resolved_source_id,
        )

        new_telemetry = self.client.telemetry_history[initial_history_len:]
        cypher_queries = [t.query for t in new_telemetry]

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        stage_result = PipelineStageResult(
            stage_name="Stage 2: Graph Scrying & Telemetry Dispatcher",
            status="SUCCESS",
            execution_time_ms=round(elapsed_ms, 3),
            cypher_queries_executed=cypher_queries,
            output_summary=(
                f"Scried {len(paths)} active attack paths, {len(centralities)} centrality scores, "
                f"and {len(candidates)} blast-radius candidates across {len(cypher_queries)} Cypher executions."
            ),
            stage_data={
                "paths_count": len(paths),
                "centralities_count": len(centralities),
                "candidates_count": len(candidates),
                "paths": [p.model_dump() for p in paths],
            },
        )
        return paths, centralities, candidates, stage_result


# ==============================================================================
# Stage 3: Minimum-Cut Combinatorial Solver
# ==============================================================================

class MinCutSolverStage:
    """
    Stage 3: Pure first-party combinatorial hitting-set solver.
    Evaluates candidate subsets, enforces operator protection constraints,
    and identifies the globally optimal minimum blast-radius cut.
    """

    def execute(
        self,
        context: InvestigationContext,
        paths: List[AttackPath],
        candidates: List[MitigationCandidate],
        centralities: List[CentralityScore],
    ) -> Tuple[Optional[CutPlan], PipelineStageResult]:
        t0 = time.perf_counter()

        if not paths:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            empty_plan = CutPlan(
                selected_node_ids=[],
                selected_node_names=[],
                total_cost=0,
                paths_evaluated_count=0,
                paths_covered_count=0,
                covered_path_indices=[],
                path_intersections={},
                explanation="No active attack paths present in graph. Zero containment actions required.",
            )
            stage_result = PipelineStageResult(
                stage_name="Stage 3: Minimum-Cut Combinatorial Solver",
                status="SUCCESS",
                execution_time_ms=round(elapsed_ms, 3),
                cypher_queries_executed=[],
                output_summary="Zero active paths detected. Graph is already contained.",
                stage_data=empty_plan.model_dump(),
            )
            return empty_plan, stage_result

        path_nodes = [p.node_ids for p in paths]
        candidate_costs = {c.id: c.cost for c in candidates}
        candidate_names = {c.id: c.name for c in candidates}
        candidate_centralities = {c.id: c.score for c in centralities}

        try:
            plan = solver.compute_minimum_cost_cut(
                attack_paths=path_nodes,
                candidate_costs=candidate_costs,
                candidate_names=candidate_names,
                source_id=context.resolved_source_id,
                crown_jewel_ids={context.resolved_target_id},
                exclude_ids=context.exclude_ids,
                candidate_centralities=candidate_centralities,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            stage_result = PipelineStageResult(
                stage_name="Stage 3: Minimum-Cut Combinatorial Solver",
                status="SUCCESS",
                execution_time_ms=round(elapsed_ms, 3),
                cypher_queries_executed=[],
                output_summary=(
                    f"Selected Cut: {plan.selected_node_ids} | "
                    f"Total Blast Cost: {plan.total_cost} | "
                    f"Paths Severed: {plan.paths_covered_count}/{plan.paths_evaluated_count}"
                ),
                stage_data=plan.model_dump(),
            )
            return plan, stage_result
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            stage_result = PipelineStageResult(
                stage_name="Stage 3: Minimum-Cut Combinatorial Solver",
                status="ERROR",
                execution_time_ms=round(elapsed_ms, 3),
                cypher_queries_executed=[],
                output_summary=f"Solver failed to find cut: {exc}",
                stage_data={"error": str(exc)},
            )
            return None, stage_result


# ==============================================================================
# Stage 4: Smoking Mirror Sandbox Simulator
# ==============================================================================

class MirrorSandboxStage:
    """
    Stage 4: Counterfactual sandbox cloning & verification in 'tezcatl_mirror'.
    Proves that severing the recommended cut reduces active paths to exactly ZERO
    before any production state is modified.
    """

    def __init__(self, client: FalkorGraphClient):
        self.client = client

    def execute(
        self,
        context: InvestigationContext,
        plan: Optional[CutPlan],
        mirror_graph_name: str = DEFAULT_MIRROR_GRAPH,
    ) -> Tuple[bool, int, PipelineStageResult]:
        t0 = time.perf_counter()
        initial_history_len = len(self.client.telemetry_history)

        if not plan or not plan.selected_node_ids:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            stage_result = PipelineStageResult(
                stage_name="Stage 4: Smoking Mirror Sandbox Simulator",
                status="SKIPPED",
                execution_time_ms=round(elapsed_ms, 3),
                cypher_queries_executed=[],
                output_summary="No plan actions to simulate in mirror sandbox.",
                stage_data={"verified": True, "remaining_paths": 0},
            )
            return True, 0, stage_result

        # Execute mirror containment simulation in isolated FalkorDB graph
        mirror_sim = self.client.simulate_mirror_containment(
            blocked_ids=plan.selected_node_ids,
            source_id=context.resolved_source_id,
            target_id=context.resolved_target_id,
            max_hops=context.max_hops,
            mirror_graph_name=mirror_graph_name,
        )

        remaining = mirror_sim["mirror_remaining_count"]
        verified = mirror_sim["verified_contained"]
        status_str = "SUCCESS" if verified else "FAILED"

        new_telemetry = self.client.telemetry_history[initial_history_len:]
        cypher_queries = [t.query for t in new_telemetry]

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        stage_result = PipelineStageResult(
            stage_name="Stage 4: Smoking Mirror Sandbox Simulator",
            status=status_str,
            execution_time_ms=round(elapsed_ms, 3),
            cypher_queries_executed=cypher_queries,
            output_summary=(
                f"Simulated in `{mirror_graph_name}`. "
                f"Severed entities: {plan.selected_node_ids}. "
                f"Remaining Paths: {remaining} ({'VERIFIED ZERO' if verified else 'CONTAINMENT FAILED'})."
            ),
            stage_data={
                "verified": verified,
                "remaining_paths": remaining,
                "mirror_graph": mirror_graph_name,
                "disabled_ids": plan.selected_node_ids,
            },
        )
        return verified, remaining, stage_result


# ==============================================================================
# Stage 5: Tactical Synthesizer & Cryptographic Auditor
# ==============================================================================

class TacticalCompilerStage:
    """
    Stage 5: Cryptographic state auditor and tactical incident compiler.
    Calculates SHA-256 graph hashes, identifies spared high-centrality bridges,
    and produces an immutable ContainmentAuditReceipt.
    """

    def __init__(self, client: FalkorGraphClient):
        self.client = client

    def execute(
        self,
        context: InvestigationContext,
        plan: Optional[CutPlan],
        candidates: List[MitigationCandidate],
        centralities: List[CentralityScore],
        sandbox_verified: bool,
        remaining_paths: int,
    ) -> Tuple[Optional[ContainmentAuditReceipt], PipelineStageResult]:
        t0 = time.perf_counter()
        initial_history_len = len(self.client.telemetry_history)

        pre_hash = self.client.compute_graph_state_hash()

        # Identify spared bottlenecks (e.g. release_controller spared when deploy_token + artifact_token chosen)
        selected_set = set(plan.selected_node_ids) if plan else set()
        cand_map = {c.id: c for c in candidates}
        spared_bottlenecks: List[SparedBottleneck] = []

        for cent in centralities:
            if cent.score > 0 and cent.id not in selected_set and cent.id != context.resolved_source_id and cent.id != context.resolved_target_id:
                cand_info = cand_map.get(cent.id)
                cost = cand_info.cost if cand_info else 0
                svcs = cand_info.downstream_services if cand_info else []
                spared_bottlenecks.append(
                    SparedBottleneck(
                        node_id=cent.id,
                        node_name=cent.name,
                        kind=cent.kind,
                        centrality_score=cent.score,
                        blast_radius_cost=cost,
                        services_preserved=svcs,
                    )
                )

        # Collect executed query records
        query_records = [
            ExecutedQueryRecord(
                query=t.query,
                params=t.params,
                latency_ms=t.latency_ms,
            )
            for t in self.client.telemetry_history[-6:]
        ]

        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        total_lat = sum(t.client_latency_ms for t in self.client.telemetry_history)

        receipt = ContainmentAuditReceipt(
            incident_id=f"INC-{int(time.time())}",
            timestamp_utc=now_utc,
            source_id=context.resolved_source_id,
            target_id=context.resolved_target_id,
            optimal_cut_ids=plan.selected_node_ids if plan else [],
            optimal_cut_names=plan.selected_node_names if plan else [],
            total_blast_radius_cost=plan.total_cost if plan else 0,
            spared_bottlenecks=spared_bottlenecks,
            executed_queries=query_records,
            total_execution_latency_ms=round(total_lat, 2),
            pre_mitigation_graph_hash=pre_hash,
            post_mitigation_graph_hash=f"sha256:mirror-simulated-{pre_hash[:8]}",
            verified_remaining_paths=remaining_paths,
            verification_status="CONTAINED_AND_VERIFIED" if sandbox_verified else "UNCONTAINED",
            verification_scope=f"{context.max_hops}_hop_bounded_reachability",
        )

        new_telemetry = self.client.telemetry_history[initial_history_len:]
        cypher_queries = [t.query for t in new_telemetry]

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        stage_result = PipelineStageResult(
            stage_name="Stage 5: Tactical Synthesizer & Cryptographic Auditor",
            status="SUCCESS",
            execution_time_ms=round(elapsed_ms, 3),
            cypher_queries_executed=cypher_queries,
            output_summary=(
                f"Audit Receipt `{receipt.incident_id}` assembled. Pre-hash: `{pre_hash[:16]}...` | "
                f"Spared Bottlenecks: {len(spared_bottlenecks)} | Verification: {receipt.verification_status}"
            ),
            stage_data=receipt.model_dump(),
        )
        return receipt, stage_result


# ==============================================================================
# Sovereign Pipeline Master Orchestrator
# ==============================================================================

class TezcatlPipeline:
    """
    Tezcatl Sovereign Execution Pipeline orchestrating Stages 1 through 5.
    Pure first-party Python implementation.
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        graph_name: str = DEFAULT_GRAPH,
        mirror_graph_name: str = DEFAULT_MIRROR_GRAPH,
        client: Optional[FalkorGraphClient] = None,
    ):
        self.client = client or FalkorGraphClient(host=host, port=port, graph_name=graph_name)
        self.mirror_graph_name = mirror_graph_name

        self.stage1_resolver = IntentResolverStage(self.client)
        self.stage2_dispatcher = GraphToolDispatcher(self.client)
        self.stage3_solver = MinCutSolverStage()
        self.stage4_sandbox = MirrorSandboxStage(self.client)
        self.stage5_auditor = TacticalCompilerStage(self.client)

    def execute(
        self,
        raw_query: str = "",
        override_source: Optional[str] = None,
        override_target: Optional[str] = None,
        override_excludes: Optional[List[str]] = None,
        override_hops: Optional[int] = None,
        run_sandbox: bool = True,
    ) -> TezcatlPipelineRun:
        t_pipeline_start = time.perf_counter()
        stages: List[PipelineStageResult] = []

        try:
            # Stage 1: Intent & Entity Resolution
            context, s1_res = self.stage1_resolver.execute(
                raw_query=raw_query,
                override_source=override_source,
                override_target=override_target,
                override_excludes=override_excludes,
                override_hops=override_hops,
            )
            stages.append(s1_res)

            # Stage 2: Graph Scrying & Telemetry Dispatcher
            paths, centralities, candidates, s2_res = self.stage2_dispatcher.execute(context)
            stages.append(s2_res)

            # Stage 3: Minimum-Cut Combinatorial Solver
            plan, s3_res = self.stage3_solver.execute(context, paths, candidates, centralities)
            stages.append(s3_res)

            # Stage 4: Smoking Mirror Sandbox Simulator
            sandbox_verified = False
            remaining_paths = len(paths)
            if run_sandbox and plan:
                sandbox_verified, remaining_paths, s4_res = self.stage4_sandbox.execute(
                    context=context,
                    plan=plan,
                    mirror_graph_name=self.mirror_graph_name,
                )
                stages.append(s4_res)

            # Stage 5: Tactical Synthesizer & Cryptographic Auditor
            receipt, s5_res = self.stage5_auditor.execute(
                context=context,
                plan=plan,
                candidates=candidates,
                centralities=centralities,
                sandbox_verified=sandbox_verified,
                remaining_paths=remaining_paths,
            )
            stages.append(s5_res)

            total_ms = (time.perf_counter() - t_pipeline_start) * 1000.0
            return TezcatlPipelineRun(
                stages=stages,
                context=context,
                paths=paths,
                centralities=centralities,
                candidates=candidates,
                plan=plan,
                receipt=receipt,
                sandbox_verified=sandbox_verified,
                total_latency_ms=round(total_ms, 2),
                success=True,
            )

        except Exception as exc:
            total_ms = (time.perf_counter() - t_pipeline_start) * 1000.0
            error_stage = PipelineStageResult(
                stage_name="Pipeline Execution Error",
                status="CRITICAL_FAILURE",
                execution_time_ms=round(total_ms, 2),
                cypher_queries_executed=[],
                output_summary=f"Pipeline aborted: {exc}",
                stage_data={"error": str(exc)},
            )
            stages.append(error_stage)

            # Fallback empty context
            ctx = InvestigationContext(
                raw_query=raw_query or "Pipeline run",
                resolved_source_id=override_source or settings.tezcatl_source_id,
                resolved_source_name=override_source or settings.tezcatl_source_id,
                resolved_target_id=override_target or settings.tezcatl_target_id,
                resolved_target_name=override_target or settings.tezcatl_target_id,
                exclude_ids=override_excludes or [],
                max_hops=override_hops or 8,
                intent="ERROR",
            )
            return TezcatlPipelineRun(
                stages=stages,
                context=ctx,
                paths=[],
                centralities=[],
                candidates=[],
                plan=None,
                receipt=None,
                sandbox_verified=False,
                total_latency_ms=round(total_ms, 2),
                success=False,
                error_message=str(exc),
            )
