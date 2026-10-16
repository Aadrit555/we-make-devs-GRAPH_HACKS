"""
TEZCATL — Graph-Native Security Containment Agent (FalkorDB)
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""

import os
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from config import settings
from graph_client import (
    FalkorGraphClient,
    validate_node_id,
    DatabaseConnectionError,
    GraphQueryError,
)
from agent import TezcatlAgent
from mcp_server import McpServer
import seed
from models import (
    IncidentAnalysisResult,
    ContainmentAuditReceipt,
    MutationResult,
    GraphFreshnessError,
)

# Initialize application
app = FastAPI(
    title="TEZCATL // Graph Containment Engine",
    description="Multi-Hop Breach Discovery, Service Impact Analysis & Shadow-Graph Verification powered by FalkorDB",
    version="2.0.0",
)

# Mount assets directory for brand crest and imagery
ASSETS_DIR = os.path.join(os.path.dirname(__file__), "assets")
if os.path.exists(ASSETS_DIR):
    app.mount("/assets", StaticFiles(directory=ASSETS_DIR), name="assets")
    app.mount("/static/assets", StaticFiles(directory=ASSETS_DIR), name="static_assets")

# Initialize singletons
graph_client = FalkorGraphClient(
    host=settings.falkordb_host,
    port=settings.falkordb_port,
    graph_name=settings.falkordb_graph,
)
mcp_server = McpServer(client=graph_client)
agent = TezcatlAgent(
    host=settings.falkordb_host,
    port=settings.falkordb_port,
    graph_name=settings.falkordb_graph,
    mirror_graph_name=settings.falkordb_mirror_graph,
    client=graph_client,
    mcp=mcp_server,
)

FRONTEND_PATH = os.path.join(os.path.dirname(__file__), "frontend", "index.html")


def resolve_entity_id(raw_id: str) -> str:
    """Normalize user-facing dropdown aliases and stylized entity names."""
    clean = raw_id.strip().lower()
    mapping = {
        "ci-runner-07": "ci_runner",
        "ci_runner": "ci_runner",
        "cirunner": "ci_runner",
        "runner": "ci_runner",
        "staging-worker-02": "staging_deployer",
        "staging_worker": "staging_deployer",
        "staging_deployer": "staging_deployer",
        "tok-deploy-alpha": "deploy_token",
        "deploy_token": "deploy_token",
        "tok-artifact-rw": "artifact_token",
        "artifact_token": "artifact_token",
        "role-cloud-deployer": "production_deploy_role",
        "production_deploy_role": "production_deploy_role",
        "pkg-registry-core": "artifact_registry",
        "artifact_registry": "artifact_registry",
        "session-legacy-deploy": "legacy_release_session",
        "legacy_release_session": "legacy_release_session",
        "release-controller": "release_controller",
        "release_controller": "release_controller",
        "role-release-signer": "signer_role",
        "signer_role": "signer_role",
        "prod-signing-key": "signing_key",
        "signing_key": "signing_key",
    }
    return mapping.get(clean, clean.replace("-", "_"))


# ==============================================================================
# Request / Response Schemas
# ==============================================================================

class InvestigateRequest(BaseModel):
    source_id: str = Field(default="ci_runner")
    target_id: Optional[str] = Field(default="signing_key")
    max_hops: int = Field(default=8, ge=1, le=8)
    exclude_ids: List[str] = Field(default_factory=list)
    raw_query: str = Field(default="")


class ContainRequest(BaseModel):
    source_id: str = Field(default="ci_runner")
    target_id: str = Field(default="signing_key")
    cut_node_ids: Optional[List[str]] = None
    cut_nodes: Optional[List[str]] = None
    blast_cost: Optional[int] = 0
    incident_id: str = Field(default="INC-TEZCATL-COMMIT")
    max_hops: int = Field(default=8, ge=1, le=8)


class StressBypassRequest(BaseModel):
    action: str = Field(default="inject", pattern=r"^(inject|remove)$")
    source_id: str = Field(default="ci_runner")
    target_id: str = Field(default="signing_key")
    evidence_id: str = Field(default="E-BYPASS-STRESS")


class MutateBypassRequest(BaseModel):
    source_id: str = Field(default="ci_runner")


class StressCostRequest(BaseModel):
    node_id: str
    new_cost: int = Field(ge=0)


# ==============================================================================
# HTTP Routes
# ==============================================================================

@app.get("/", response_class=FileResponse)
def serve_index():
    """Serve the minimal Meadow Landing UI."""
    if not os.path.exists(FRONTEND_PATH):
        raise HTTPException(status_code=404, detail="frontend/index.html not found.")
    return FileResponse(FRONTEND_PATH, media_type="text/html")


@app.get("/api/health")
def get_health():
    """Verify live FalkorDB connectivity and return graph statistics."""
    try:
        is_connected = graph_client.check_connection(auto_bootstrap=True)
        if not is_connected:
            return JSONResponse(
                status_code=503,
                content={"status": "DATABASE_DISCONNECTED", "host": settings.falkordb_host, "port": settings.falkordb_port},
            )

        node_res = graph_client.graph.query("MATCH (n:Entity) RETURN count(n) AS cnt")
        edge_res = graph_client.graph.query("MATCH ()-[r]->() RETURN count(r) AS cnt")
        node_count = int(node_res.result_set[0][0]) if node_res.result_set else 0
        edge_count = int(edge_res.result_set[0][0]) if edge_res.result_set else 0

        return {
            "status": "HEALTHY",
            "host": settings.falkordb_host,
            "port": settings.falkordb_port,
            "graph": settings.falkordb_graph,
            "mirror_graph": settings.falkordb_mirror_graph,
            "node_count": node_count,
            "edge_count": edge_count,
        }
    except Exception as exc:
        return JSONResponse(
            status_code=503,
            content={"status": "ERROR", "detail": str(exc)},
        )


@app.get("/api/state")
def get_graph_state(source_id: str = Query(default="ci_runner")):
    """
    Returns full structured state for the interactive workspace console:
    - Active path count and discovered variable-length routes (*1..8)
    - Ranked betweenness centrality & dynamic service blast costs
    - Minimum-cut solution verified in tezcatl_mirror sandbox
    - Live OpenCypher query telemetry
    """
    resolved_source = resolve_entity_id(source_id)
    try:
        analysis, stages = agent.run_investigation(
            override_source=resolved_source,
            override_target="signing_key",
            override_hops=8,
            run_mirror_sim=True,
        )

        # Centrality score map for quick lookup
        cent_map = {c.id: c.score for c in analysis.centrality_scores}

        candidates_data = [
            {
                "id": c.id,
                "centrality": round(cent_map.get(c.id, 0.0), 3),
                "blast_cost": c.cost,
                "services": c.downstream_services,
            }
            for c in analysis.eligible_candidates
        ]

        paths_data = [
            {
                "path_id": f"ROUTE-{i+1}",
                "hops": p.hops,
                "nodes": [{"id": nid} for nid in p.node_ids],
                "mechanisms": p.mechanisms,
                "evidence_ids": p.evidence_ids,
            }
            for i, p in enumerate(analysis.discovered_paths)
        ]

        optimal_cut = None
        if analysis.recommended_plan and analysis.recommended_plan.selected_node_ids:
            optimal_cut = {
                "cut_nodes": analysis.recommended_plan.selected_node_ids,
                "cut_names": analysis.recommended_plan.selected_node_names,
                "blast_cost": analysis.recommended_plan.total_cost,
            }

        telemetry_data = [
            {
                "graph": settings.falkordb_graph,
                "execution_ms": t.latency_ms,
                "cypher": t.query,
            }
            for t in graph_client.telemetry_history[-6:]
        ]

        return {
            "source_id": resolved_source,
            "target_id": analysis.target_id,
            "active_path_count": len(analysis.discovered_paths),
            "paths": paths_data,
            "candidates": candidates_data,
            "cut_solution": {
                "optimal": optimal_cut,
            },
            "mirror_proof": analysis.mirror_simulation,
            "telemetry": telemetry_data,
            "graph_is_contained": analysis.graph_is_contained,
            "pre_mitigation_hash": analysis.pre_mitigation_hash,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch graph state: {exc}")


@app.post("/api/investigate")
def run_investigation(req: InvestigateRequest):
    """
    Executes the 5-stage Tezcatl pipeline via FalkorDB & MCP tools:
    1. Intent & Entity Resolution
    2. Multi-hop Path Discovery (*1..8) & algo.betweenness centrality
    3. Combinatorial Minimum-Cut Solver
    4. Shadow Graph Sandbox (tezcatl_mirror vs. prod_graph)
    5. SHA-256 Containment Audit Receipt Synthesis
    """
    try:
        resolved_source = resolve_entity_id(req.source_id)
        analysis, stages = agent.run_investigation(
            raw_query=req.raw_query,
            override_source=resolved_source,
            override_target=req.target_id,
            override_excludes=req.exclude_ids,
            override_hops=req.max_hops,
            run_mirror_sim=True,
        )
        return {
            "analysis": analysis.model_dump(),
            "stages": [s.model_dump() for s in stages],
        }
    except (ValueError, GraphQueryError, DatabaseConnectionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Investigation failed: {exc}")


@app.post("/api/contain")
def commit_containment(req: ContainRequest):
    """
    Gated human-authorized containment action:
    1. Checks freshness of active attack paths.
    2. Isolates cut nodes in production graph via parameterized Cypher.
    3. Executes fresh post-action reachability query to verify 0 remaining paths.
    4. Issues immutable SHA-256 Containment Audit Receipt.
    """
    try:
        chosen_cuts = req.cut_node_ids or req.cut_nodes or []
        if not chosen_cuts:
            raise HTTPException(status_code=400, detail="cut_node_ids or cut_nodes must be non-empty.")

        resolved_source = resolve_entity_id(req.source_id)
        current_paths = graph_client.discover_attack_paths(
            source_id=resolved_source, target_id=req.target_id, max_hops=req.max_hops
        )
        pre_paths = len(current_paths)

        mutation, receipt = agent.execute_containment(
            source_id=resolved_source,
            target_id=req.target_id,
            expected_cut_ids=chosen_cuts,
            incident_id=req.incident_id,
            max_hops=req.max_hops,
        )

        return {
            "pre_paths": pre_paths,
            "post_paths": receipt.verified_remaining_paths,
            "sha256_receipt": receipt.post_mitigation_graph_hash,
            "mutation": mutation.model_dump(),
            "receipt": receipt.model_dump(),
            "status": "CONTAINED_AND_VERIFIED" if receipt.verified_remaining_paths == 0 else "PARTIAL",
        }
    except GraphFreshnessError as gfe:
        raise HTTPException(status_code=409, detail=str(gfe))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Containment commit failed: {exc}")


@app.post("/api/reset")
def reset_database():
    """Restores the pristine seeded FalkorDB topology."""
    try:
        seed.seed_database(
            host=settings.falkordb_host,
            port=settings.falkordb_port,
            graph_name=settings.falkordb_graph,
        )
        return {"status": "SUCCESS", "message": "Graph restored to pristine seed topology."}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to reset graph: {exc}")


@app.post("/api/mutate/bypass")
def toggle_mutate_bypass(req: MutateBypassRequest):
    """Toggles or injects a bypass edge for stress testing."""
    resolved_source = resolve_entity_id(req.source_id)
    try:
        # Check if bypass exists
        check_q = "MATCH ()-[r:ATTACK_STEP {evidence_id: $ev}]->() RETURN count(r) AS cnt"
        res = graph_client._execute_query(check_q, {"ev": "E-BYPASS-STRESS"}, read_only=True)
        exists = int(res.result_set[0][0]) if res.result_set else 0

        if exists > 0:
            deleted = graph_client.remove_bypass_edge("E-BYPASS-STRESS")
            return {"status": "SUCCESS", "action": "removed", "edges_deleted": deleted}
        else:
            created = graph_client.inject_bypass_edge(
                source_id=resolved_source,
                target_id="signing_key",
                evidence_id="E-BYPASS-STRESS",
            )
            return {"status": "SUCCESS", "action": "injected", "edges_created": created}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/stress/bypass")
def toggle_bypass_route(req: StressBypassRequest):
    """Injects or removes a direct or lateral bypass edge for stress testing."""
    try:
        if req.action == "inject":
            created = graph_client.inject_bypass_edge(
                source_id=resolve_entity_id(req.source_id),
                target_id=req.target_id,
                evidence_id=req.evidence_id,
            )
            return {"action": "injected", "edges_created": created}
        else:
            deleted = graph_client.remove_bypass_edge(evidence_id=req.evidence_id)
            return {"action": "removed", "edges_deleted": deleted}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/stress/cost")
def update_node_cost(req: StressCostRequest):
    """Mutates an entity's disruption cost to test dynamic optimizer reaction."""
    try:
        res = graph_client.update_node_cost(node_id=req.node_id, new_cost=req.new_cost)
        return {"status": "SUCCESS", "node_id": req.node_id, "new_cost": req.new_cost, "updated": res}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/mcp")
async def mcp_endpoint(request: Request):
    """First-party JSON-RPC 2.0 Model Context Protocol tool dispatcher."""
    try:
        body = await request.json()
        response = mcp_server.handle_request(body)
        return response
    except Exception as exc:
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32603, "message": f"MCP execution error: {exc}"},
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
