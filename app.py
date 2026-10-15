"""
TEZCATL Sovereign Graph Engine — Authored by Aadrit555
app.py — Production FastAPI Gateway & Sovereign Agent Server.

Endpoints:
- GET  /                  -> Driftbar Meadow Footer Hero & Frosted Glass SecOps Console
- GET  /api/health        -> Real-time FalkorDB graph connectivity & topology stats
- POST /api/investigate   -> 5-Stage deterministic scrying, betweenness & mirror sandbox
- POST /api/contain       -> Gated human containment commit & post-action zero-path verification
- POST /api/reset         -> Restore pristine FalkorDB topology
- POST /api/stress/bypass -> Inject/remove stress-test bypass route
- POST /api/stress/cost   -> Mutate node disruption cost
- POST /api/mcp           -> JSON-RPC 2.0 Model Context Protocol tool endpoint

Zero external APIs, zero third-party agent frameworks. 100% first-party sovereign Python.
"""

import os
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
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
    title="TEZCATL // Obsidian Mirror Graph Containment Engine",
    description="Multi-Hop Breach Discovery, Blast-Radius Calculus & Shadow-Graph Verification powered by FalkorDB",
    version="2.0.0",
)

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
    cut_node_ids: List[str] = Field(..., min_length=1)
    incident_id: str = Field(default="INC-TEZCATL-COMMIT")
    max_hops: int = Field(default=8, ge=1, le=8)


class StressBypassRequest(BaseModel):
    action: str = Field(default="inject", pattern=r"^(inject|remove)$")
    source_id: str = Field(default="ci_runner")
    target_id: str = Field(default="signing_key")
    evidence_id: str = Field(default="E-BYPASS-STRESS")


class StressCostRequest(BaseModel):
    node_id: str
    new_cost: int = Field(ge=0)


# ==============================================================================
# HTTP Routes
# ==============================================================================

@app.get("/", response_class=FileResponse)
def serve_index():
    """Serve the clean-room brutalist Driftbar Meadow UI."""
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


@app.post("/api/investigate")
def run_investigation(req: InvestigateRequest):
    """
    Executes the 5-stage Tezcatl sovereign pipeline via FalkorDB & MCP tools:
    1. Intent & Entity Resolution
    2. Multi-hop Scrying (*1..8) & algo.betweenness centrality
    3. Combinatorial Minimum-Cut Solver
    4. Smoking Mirror Sandbox (tezcatl_mirror vs. prod_graph)
    5. SHA-256 Containment Audit Receipt Synthesis
    """
    try:
        analysis, stages = agent.run_investigation(
            raw_query=req.raw_query,
            override_source=req.source_id,
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
        mutation, receipt = agent.execute_containment(
            source_id=req.source_id,
            target_id=req.target_id,
            expected_cut_ids=req.cut_node_ids,
            incident_id=req.incident_id,
            max_hops=req.max_hops,
        )
        return {
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


@app.post("/api/stress/bypass")
def toggle_bypass_route(req: StressBypassRequest):
    """Injects or removes a direct or lateral bypass edge for stress testing."""
    try:
        if req.action == "inject":
            created = graph_client.inject_bypass_edge(
                source_id=req.source_id,
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
