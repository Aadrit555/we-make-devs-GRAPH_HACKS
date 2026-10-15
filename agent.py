"""
TEZCATL Sovereign Graph Engine — Authored by Aadrit555
agent.py — Track 01 Sovereign Agent Orchestrator.

Autonomous incident containment agent powered natively by FalkorDB:
- Multi-hop OpenCypher attack-path discovery (*1..8)
- Native algo.betweenness centrality ranking
- Dynamic downstream service blast-radius calculation
- JSON-RPC 2.0 Model Context Protocol (MCP) tool dispatch
- Shadow-graph mirror verification in tezcatl_mirror
- Cryptographic SHA-256 graph state receipts
Zero external APIs, zero third-party agent frameworks.
"""

import time
import json
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from config import settings
from graph_client import FalkorGraphClient, validate_node_id, DEFAULT_HOST, DEFAULT_PORT, DEFAULT_GRAPH, DEFAULT_MIRROR_GRAPH
from mcp_server import McpServer
import solver
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
    IncidentAnalysisResult,
    MutationResult,
    GraphFreshnessError,
)


class TezcatlAgent:
    """
    Sovereign Track 01 Autonomous Agent for TEZCATL.
    Dispatches graph tools via first-party JSON-RPC 2.0 MCP interface.
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        graph_name: str = DEFAULT_GRAPH,
        mirror_graph_name: str = DEFAULT_MIRROR_GRAPH,
        client: Optional[FalkorGraphClient] = None,
        mcp: Optional[McpServer] = None,
    ):
        self.client = client or FalkorGraphClient(host=host, port=port, graph_name=graph_name)
        self.mirror_graph_name = mirror_graph_name
        self.mcp = mcp or McpServer(client=self.client)

    def run_investigation(
        self,
        raw_query: str = "",
        override_source: Optional[str] = None,
        override_target: Optional[str] = None,
        override_excludes: Optional[List[str]] = None,
        override_hops: Optional[int] = None,
        run_mirror_sim: bool = True,
    ) -> Tuple[IncidentAnalysisResult, List[PipelineStageResult]]:
        """
        Executes complete 5-stage sovereign investigation via MCP tool dispatch.
        Returns IncidentAnalysisResult and list of PipelineStageResults.
        """
        stages: List[PipelineStageResult] = []
        t_pipeline_start = time.perf_counter()

        # ----------------------------------------------------------------------
        # Stage 1: Intent & Entity Resolution (Zero External APIs)
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        catalog_query = "MATCH (n:Entity) RETURN n.id AS id, n.name AS name, n.criticality AS criticality"
        res = self.client._execute_query(catalog_query)

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

        resolved_source = override_source or ""
        if not resolved_source and raw_query:
            query_lower = raw_query.lower()
            for name_term, eid in id_by_lower_name.items():
                if name_term in query_lower and "crown" not in known_entities[eid]["criticality"]:
                    if any(term in query_lower for term in ["runner", "ci", "compromised", "source", "ingress"]):
                        resolved_source = eid
                        break
                    elif not resolved_source:
                        resolved_source = eid

        if not resolved_source or resolved_source not in known_entities:
            resolved_source = settings.tezcatl_source_id

        resolved_target = override_target or ""
        if not resolved_target and raw_query:
            query_lower = raw_query.lower()
            for name_term, eid in id_by_lower_name.items():
                if name_term in query_lower and known_entities[eid]["criticality"] == "crown_jewel":
                    resolved_target = eid
                    break

        if not resolved_target or resolved_target not in known_entities:
            resolved_target = crown_jewels[0] if crown_jewels else settings.tezcatl_target_id

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

        resolved_hops = override_hops or 8
        if raw_query and not override_hops:
            hops_match = re.search(r"(\d+)\s*hops?", raw_query.lower())
            if hops_match:
                try:
                    resolved_hops = max(1, min(8, int(hops_match.group(1))))
                except ValueError:
                    pass

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
        stages.append(PipelineStageResult(
            stage_name="Stage 1: Intent & Entity Resolution",
            status="SUCCESS",
            execution_time_ms=round(elapsed_ms, 3),
            cypher_queries_executed=[catalog_query],
            output_summary=f"Resolved Source: `{resolved_source}` | Target: `{resolved_target}` | Protected Excludes: {resolved_excludes or 'None'}",
            stage_data=context.model_dump(),
        ))

        # ----------------------------------------------------------------------
        # Stage 2: Graph Scrying & Telemetry via JSON-RPC MCP Tool Dispatch
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        initial_history_len = len(self.client.telemetry_history)

        # 1. MCP Call: scry_attack_paths
        raw_paths = self.mcp.call_tool("scry_attack_paths", {
            "source_id": context.resolved_source_id,
            "target_id": context.resolved_target_id,
            "max_hops": context.max_hops,
        })
        paths = [AttackPath(**p) for p in raw_paths]

        # 2. MCP Call: rank_betweenness_bottlenecks
        raw_centrality = self.mcp.call_tool("rank_betweenness_bottlenecks", {})
        centralities = [CentralityScore(**c) for c in raw_centrality]

        # 3. MCP Call: compute_service_blast_radius
        all_path_nodes = list(dict.fromkeys([nid for p in paths for nid in p.node_ids]))
        raw_candidates = self.mcp.call_tool("compute_service_blast_radius", {
            "path_node_ids": all_path_nodes,
            "source_id": context.resolved_source_id,
        })
        candidates = [MitigationCandidate(**c) for c in raw_candidates]

        new_telemetry = self.client.telemetry_history[initial_history_len:]
        cypher_queries = [t.query for t in new_telemetry]

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        stages.append(PipelineStageResult(
            stage_name="Stage 2: Graph Scrying & Telemetry Dispatcher (MCP)",
            status="SUCCESS",
            execution_time_ms=round(elapsed_ms, 3),
            cypher_queries_executed=cypher_queries,
            output_summary=f"Scried {len(paths)} paths, {len(centralities)} centralities, {len(candidates)} candidates via MCP dispatch.",
            stage_data={"paths_count": len(paths), "centralities_count": len(centralities), "candidates_count": len(candidates)},
        ))

        # ----------------------------------------------------------------------
        # Stage 3: Combinatorial Minimum-Cut Solver
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        plan: Optional[CutPlan] = None
        if paths:
            path_nodes = [p.node_ids for p in paths]
            candidate_costs = {c.id: c.cost for c in candidates}
            candidate_names = {c.id: c.name for c in candidates}
            candidate_centralities = {c.id: c.score for c in centralities}

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
        stages.append(PipelineStageResult(
            stage_name="Stage 3: Minimum-Cut Combinatorial Solver",
            status="SUCCESS",
            execution_time_ms=round(elapsed_ms, 3),
            cypher_queries_executed=[],
            output_summary=f"Selected Cut: {plan.selected_node_ids if plan else []} | Total Cost: {plan.total_cost if plan else 0}",
            stage_data=plan.model_dump() if plan else {},
        ))

        # ----------------------------------------------------------------------
        # Stage 4: Smoking Mirror Sandbox Simulator via MCP Dispatch
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        sandbox_verified = False
        remaining_paths = len(paths)
        mirror_sim: Optional[Dict[str, Any]] = None

        if run_mirror_sim and plan and plan.selected_node_ids:
            initial_history_len = len(self.client.telemetry_history)
            mirror_sim = self.mcp.call_tool("simulate_mirror_containment", {
                "blocked_ids": plan.selected_node_ids,
                "source_id": context.resolved_source_id,
                "target_id": context.resolved_target_id,
                "max_hops": context.max_hops,
                "mirror_graph_name": self.mirror_graph_name,
            })
            remaining_paths = mirror_sim["mirror_remaining_count"]
            sandbox_verified = mirror_sim["verified_contained"]

            new_telemetry = self.client.telemetry_history[initial_history_len:]
            cypher_queries = [t.query for t in new_telemetry]

            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            stages.append(PipelineStageResult(
                stage_name="Stage 4: Smoking Mirror Sandbox Simulator (MCP)",
                status="SUCCESS" if sandbox_verified else "FAILED",
                execution_time_ms=round(elapsed_ms, 3),
                cypher_queries_executed=cypher_queries,
                output_summary=f"Simulated in `{self.mirror_graph_name}`. Remaining paths: {remaining_paths} ({'VERIFIED ZERO' if sandbox_verified else 'FAILED'}).",
                stage_data=mirror_sim,
            ))
        else:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            stages.append(PipelineStageResult(
                stage_name="Stage 4: Smoking Mirror Sandbox Simulator (MCP)",
                status="SKIPPED",
                execution_time_ms=round(elapsed_ms, 3),
                cypher_queries_executed=[],
                output_summary="No cut plan actions to simulate in mirror sandbox.",
                stage_data={},
            ))

        # ----------------------------------------------------------------------
        # Stage 5: Tactical Synthesizer & Cryptographic Auditor
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        pre_hash = self.mcp.call_tool("compute_graph_state_hash", {"graph_name": self.client.graph_name})

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

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        stages.append(PipelineStageResult(
            stage_name="Stage 5: Tactical Synthesizer & Cryptographic Auditor",
            status="SUCCESS",
            execution_time_ms=round(elapsed_ms, 3),
            cypher_queries_executed=[],
            output_summary=f"Audit receipt `{receipt.incident_id}` generated with pre-hash `{pre_hash[:16]}...`",
            stage_data=receipt.model_dump(),
        ))

        analysis = IncidentAnalysisResult(
            source_id=context.resolved_source_id,
            target_id=context.resolved_target_id,
            discovered_paths=paths,
            centrality_scores=centralities,
            eligible_candidates=candidates,
            recommended_plan=plan,
            counterfactual_remaining_paths=remaining_paths,
            graph_is_contained=len(paths) == 0,
            status_message="Analysis complete via TezcatlAgent.",
            telemetry=self.client.last_telemetry,
            mirror_simulation={
                "mirror_graph_name": self.mirror_graph_name,
                "remaining_paths": remaining_paths,
                "simulation_time_ms": stages[3].execution_time_ms if len(stages) > 3 else 0.0,
            },
            pre_mitigation_hash=pre_hash,
            audit_receipt=receipt,
        )

        return analysis, stages

    def execute_containment(
        self,
        source_id: str,
        target_id: str,
        expected_cut_ids: List[str],
        incident_id: str = "INC-TEZCATL-COMMIT",
        max_hops: int = 8,
    ) -> Tuple[MutationResult, ContainmentAuditReceipt]:
        """
        Executes gated human-authorized containment action:
        1. Verifies plan freshness.
        2. Applies mutation in production graph via MCP.
        3. Verifies post-action zero remaining paths.
        4. Generates post-action cryptographic audit receipt.
        """
        validate_node_id(source_id)
        validate_node_id(target_id)
        for cid in expected_cut_ids:
            validate_node_id(cid)

        # 1. Freshness check: verify expected paths still exist
        current_paths = self.client.discover_attack_paths(source_id=source_id, target_id=target_id, max_hops=max_hops)
        if not current_paths:
            raise GraphFreshnessError("Graph state has already been contained; no active attack paths remain.")

        pre_hash = self.client.compute_graph_state_hash()

        # 2. Mutate production graph
        mutation_dict = self.mcp.call_tool("apply_containment_action", {"blocked_ids": expected_cut_ids})
        mutation_res = MutationResult(**mutation_dict)

        # 3. Fresh verification query
        post_count = self.client.count_remaining_paths(source_id=source_id, target_id=target_id, max_hops=max_hops)
        post_hash = self.client.compute_graph_state_hash()

        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        query_records = [
            ExecutedQueryRecord(
                query=t.query,
                params=t.params,
                latency_ms=t.latency_ms,
            )
            for t in self.client.telemetry_history[-4:]
        ]

        receipt = ContainmentAuditReceipt(
            incident_id=incident_id,
            timestamp_utc=now_utc,
            source_id=source_id,
            target_id=target_id,
            optimal_cut_ids=expected_cut_ids,
            optimal_cut_names=expected_cut_ids,
            total_blast_radius_cost=0,
            spared_bottlenecks=[],
            executed_queries=query_records,
            total_execution_latency_ms=round(sum(t.client_latency_ms for t in self.client.telemetry_history[-4:]), 2),
            pre_mitigation_graph_hash=pre_hash,
            post_mitigation_graph_hash=post_hash,
            verified_remaining_paths=post_count,
            verification_status="CONTAINED_AND_VERIFIED" if post_count == 0 else "CONTAINMENT_FAILED",
            verification_scope=f"{max_hops}_hop_bounded_reachability",
        )

        return mutation_res, receipt

    def verify_containment_post_action(
        self,
        source_id: str,
        target_id: str,
        max_hops: int = 8,
    ) -> int:
        """Execute fresh post-action query on production graph to confirm zero reachability."""
        return self.client.count_remaining_paths(source_id=source_id, target_id=target_id, max_hops=max_hops)
