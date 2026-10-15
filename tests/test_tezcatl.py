"""
TEZCATL Sovereign Graph Engine — Authored by Aadrit555
tests/test_tezcatl.py — Comprehensive tests for the 5-Stage Tezcatl Execution Pipeline.

Validates:
- Stage 1: Deterministic natural language tokenization and entity resolution (Zero external APIs)
- Stage 2: Parameterized Cypher tool dispatch with @tezcatl_tool
- Stage 3: Combinatorial hitting-set solver with blast radius and operator protection
- Stage 4: Smoking Mirror Sandbox simulation and zero-path verification
- Stage 5: Cryptographic audit receipt assembly and SHA-256 state hashing
- Full pipeline orchestration end-to-end
"""

import pytest
import seed
from config import settings
from graph_client import FalkorGraphClient
import solver
from pipeline import (
    TezcatlPipeline,
    IntentResolverStage,
    GraphToolDispatcher,
    MinCutSolverStage,
    MirrorSandboxStage,
    TacticalCompilerStage,
    tezcatl_tool,
)

FALKORDB_HOST = settings.falkordb_host
FALKORDB_PORT = settings.falkordb_port
PROD_GRAPH = settings.falkordb_graph
MIRROR_GRAPH = settings.falkordb_mirror_graph


@pytest.fixture(scope="module", autouse=True)
def pristine_graph():
    """Ensure clean seeded topology before testing."""
    seed.seed_database(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=PROD_GRAPH)


@pytest.fixture
def client():
    return FalkorGraphClient(host=FALKORDB_HOST, port=FALKORDB_PORT, graph_name=PROD_GRAPH)


# ==============================================================================
# Stage 1 Tests: Intent & Entity Resolution (Zero External APIs)
# ==============================================================================

def test_stage1_intent_resolution_default(client):
    stage = IntentResolverStage(client)
    ctx, result = stage.execute()

    assert result.status == "SUCCESS"
    assert ctx.resolved_source_id == "ci_runner"
    assert ctx.resolved_target_id == "signing_key"
    assert ctx.max_hops == 8
    assert ctx.exclude_ids == []


def test_stage1_intent_resolution_natural_language(client):
    stage = IntentResolverStage(client)
    nl_query = "Contain breach from ci_runner to signing_key within 5 hops protect release_controller"
    ctx, result = stage.execute(raw_query=nl_query)

    assert result.status == "SUCCESS"
    assert ctx.resolved_source_id == "ci_runner"
    assert ctx.resolved_target_id == "signing_key"
    assert ctx.max_hops == 5
    assert "release_controller" in ctx.exclude_ids


# ==============================================================================
# Stage 2 Tests: Graph Tool Dispatcher (@tezcatl_tool)
# ==============================================================================

def test_stage2_tool_decorator(client):
    dispatcher = GraphToolDispatcher(client)
    assert getattr(dispatcher.scry_attack_paths, "_is_tezcatl_tool", False) is True
    assert getattr(dispatcher.rank_betweenness_bottlenecks, "_is_tezcatl_tool", False) is True
    assert getattr(dispatcher.compute_service_blast_radius, "_is_tezcatl_tool", False) is True


def test_stage2_dispatch_execution(client):
    stage1 = IntentResolverStage(client)
    ctx, _ = stage1.execute()

    dispatcher = GraphToolDispatcher(client)
    paths, centralities, candidates, result = dispatcher.execute(ctx)

    assert result.status == "SUCCESS"
    assert len(paths) == 3
    assert len(centralities) > 0
    assert len(candidates) > 0

    # Verify native betweenness centrality finds release_controller as top bottleneck
    top_centrality = centralities[0]
    assert top_centrality.id == "release_controller"
    assert top_centrality.score > 0.0


# ==============================================================================
# Stage 3 Tests: Combinatorial Minimum-Cut Solver & Protection Constraints
# ==============================================================================

def test_stage3_solver_optimal_cost(client):
    stage1 = IntentResolverStage(client)
    ctx, _ = stage1.execute()

    stage2 = GraphToolDispatcher(client)
    paths, centralities, candidates, _ = stage2.execute(ctx)

    stage3 = MinCutSolverStage()
    plan, result = stage3.execute(ctx, paths, candidates, centralities)

    assert result.status == "SUCCESS"
    assert plan is not None
    assert plan.total_cost == 5
    assert set(plan.selected_node_ids) == {"deploy_token", "artifact_token"}
    assert plan.paths_covered_count == 3


def test_stage3_solver_with_operator_protection(client):
    """When deploy_token is protected, solver must find next best cut without it."""
    stage1 = IntentResolverStage(client)
    ctx, _ = stage1.execute(override_excludes=["deploy_token"])

    stage2 = GraphToolDispatcher(client)
    paths, centralities, candidates, _ = stage2.execute(ctx)

    stage3 = MinCutSolverStage()
    plan, result = stage3.execute(ctx, paths, candidates, centralities)

    assert result.status == "SUCCESS"
    assert plan is not None
    # deploy_token cannot be in the cut
    assert "deploy_token" not in plan.selected_node_ids
    assert plan.paths_covered_count == 3


# ==============================================================================
# Stage 4 Tests: Smoking Mirror Sandbox Simulator
# ==============================================================================

def test_stage4_mirror_sandbox_verification(client):
    stage1 = IntentResolverStage(client)
    ctx, _ = stage1.execute()

    stage2 = GraphToolDispatcher(client)
    paths, centralities, candidates, _ = stage2.execute(ctx)

    stage3 = MinCutSolverStage()
    plan, _ = stage3.execute(ctx, paths, candidates, centralities)

    stage4 = MirrorSandboxStage(client)
    verified, remaining, result = stage4.execute(ctx, plan, mirror_graph_name=MIRROR_GRAPH)

    assert result.status == "SUCCESS"
    assert verified is True
    assert remaining == 0


# ==============================================================================
# Stage 5 Tests: Tactical Synthesizer & Cryptographic Auditor
# ==============================================================================

def test_stage5_audit_receipt(client):
    stage1 = IntentResolverStage(client)
    ctx, _ = stage1.execute()

    stage2 = GraphToolDispatcher(client)
    paths, centralities, candidates, _ = stage2.execute(ctx)

    stage3 = MinCutSolverStage()
    plan, _ = stage3.execute(ctx, paths, candidates, centralities)

    stage5 = TacticalCompilerStage(client)
    receipt, result = stage5.execute(
        context=ctx,
        plan=plan,
        candidates=candidates,
        centralities=centralities,
        sandbox_verified=True,
        remaining_paths=0,
    )

    assert result.status == "SUCCESS"
    assert receipt is not None
    assert len(receipt.pre_mitigation_graph_hash) == 64
    assert receipt.post_mitigation_graph_hash.startswith("sha256:")
    assert len(receipt.optimal_cut_ids) == 2
    # Verify release_controller is among spared bottlenecks
    spared_ids = [b.node_id for b in receipt.spared_bottlenecks]
    assert "release_controller" in spared_ids


# ==============================================================================
# End-to-End TezcatlPipeline Run Test
# ==============================================================================

def test_tezcatl_pipeline_full_e2e(client):
    pipeline = TezcatlPipeline(
        host=FALKORDB_HOST,
        port=FALKORDB_PORT,
        graph_name=PROD_GRAPH,
        mirror_graph_name=MIRROR_GRAPH,
    )

    run_result = pipeline.execute(
        raw_query="Contain breach from ci_runner to signing_key within 8 hops protect release_controller"
    )

    assert run_result.success is True
    assert len(run_result.stages) == 5
    assert run_result.plan is not None
    assert run_result.plan.total_cost == 5
    assert set(run_result.plan.selected_node_ids) == {"deploy_token", "artifact_token"}
    assert run_result.sandbox_verified is True
    assert run_result.receipt is not None
    assert run_result.receipt.verification_status == "CONTAINED_AND_VERIFIED"
    assert run_result.total_latency_ms > 0.0
