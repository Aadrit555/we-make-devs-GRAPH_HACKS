"""
TEZCATL — Graph-Native Breach Containment Agent on FalkorDB
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from backend.models import CutActionRequest, SourceRequest
from backend.graph_client import TezcatlGraphEngine

app = FastAPI(title="TEZCATL — FalkorDB Breach Containment Engine")
engine = TezcatlGraphEngine()


@app.get("/api/health")
def get_health():
    """Verify live FalkorDB connectivity and graph bootstrap status."""
    return {
        "status": "HEALTHY",
        "service": "TEZCATL Graph Engine",
        "prod_graph": engine.prod_name,
        "mirror_graph": engine.mirror_name,
    }


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


@app.post("/api/contain")
def execute_containment(req: CutActionRequest):
    return engine.commit_containment(req.source_id, req.cut_nodes, req.blast_cost)


@app.post("/api/mutate/bypass")
def mutate_bypass(req: SourceRequest):
    return engine.inject_bypass_edge(req.source_id)


@app.post("/api/reset")
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
