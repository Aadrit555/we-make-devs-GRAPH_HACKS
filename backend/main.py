"""
TEZCATL — Graph-Native Breach Containment Agent on FalkorDB
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""
from contextlib import asynccontextmanager
from typing import Optional
from pathlib import Path
from fastapi import FastAPI, HTTPException, Security, Depends, status
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from backend.config import ADMIN_TOKEN, REQUIRE_AUTH
from backend.models import CutActionRequest, SourceRequest
from backend.graph_client import TezcatlGraphEngine

engine = TezcatlGraphEngine(auto_connect=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Enforce startup retries with explicit failure
    engine.connect_with_retries()
    engine.ensure_seeded()
    yield


app = FastAPI(
    title="TEZCATL — FalkorDB Breach Containment Engine",
    lifespan=lifespan,
)

api_key_header = APIKeyHeader(name="X-Tezcatl-Auth", auto_error=False)


def verify_admin_auth(api_key: Optional[str] = Security(api_key_header)) -> bool:
    """Protect state-changing endpoints on public services."""
    if not REQUIRE_AUTH:
        return True
    if api_key and api_key.strip() == ADMIN_TOKEN:
        return True
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: State-changing operations require valid X-Tezcatl-Auth token.",
    )


@app.get("/api/health")
def get_health():
    """Verify live FalkorDB connectivity and graph bootstrap status."""
    try:
        health_info = engine.check_health()
        return health_info
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"FalkorDB service unavailable: {str(e)}",
        )


@app.get("/api/state")
def get_investigation_state(source_id: str = "ci-runner-07"):
    topology, top_tel = engine.get_full_topology("prod_graph")
    paths, path_tel = engine.find_attack_paths(source_id, "prod_graph")
    candidates, calc_tels = engine.compute_centrality_and_blast_radius(paths, "prod_graph")
    cut_solution = engine.solve_minimum_cut_set(source_id, paths, candidates)

    mirror_proof = None
    mirror_tels = []
    if cut_solution["optimal"]:
        mirror_proof = engine.verify_in_shadow_mirror(
            source_id, cut_solution["optimal"]["cut_nodes"]
        )
        mirror_tels = mirror_proof.get("telemetry", [])

    return {
        "source_id": source_id,
        "topology": topology,
        "active_path_count": len(paths),
        "paths": paths,
        "candidates": candidates,
        "cut_solution": cut_solution,
        "mirror_proof": mirror_proof,
        "telemetry": [top_tel, path_tel, *calc_tels, *mirror_tels],
    }


@app.post("/api/contain", dependencies=[Depends(verify_admin_auth)])
def execute_containment(req: CutActionRequest):
    try:
        return engine.commit_containment(
            source_id=req.source_id,
            caller_cut_nodes=req.cut_nodes,
            caller_blast_cost=req.blast_cost,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except RuntimeError as re:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(re))


@app.post("/api/mutate/bypass", dependencies=[Depends(verify_admin_auth)])
def mutate_bypass(req: SourceRequest):
    return engine.inject_bypass_edge(req.source_id)


@app.post("/api/reset", dependencies=[Depends(verify_admin_auth)])
def reset_graphs():
    engine.seed_topology("prod_graph")
    engine.clone_prod_to_mirror()
    return {"status": "reset_complete"}


ROOT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT_DIR / "frontend"
ASSETS_DIR = ROOT_DIR / "assets"

if ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")

if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    def serve_ui():
        return FileResponse(str(FRONTEND_DIR / "index.html"))
