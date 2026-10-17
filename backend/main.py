"""
TEZCATL — Graph-Native Breach Containment Agent on FalkorDB
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from backend.models import (
    CutActionRequest,
    SourceRequest,
    SecurityTopologyManifest,
    ScenarioSummary,
)
from backend.graph_client import TezcatlGraphEngine
from backend.scenarios import SCENARIO_REGISTRY
from backend.config import PROD_GRAPH, MIRROR_GRAPH, MAX_MANIFEST_BYTES

app = FastAPI(title="TEZCATL — FalkorDB Breach Containment Engine")
engine = TezcatlGraphEngine()


def bootstrap_all_scenarios():
    """Seeds baseline and isolated scenarios into FalkorDB on startup."""
    for s_id, entry in SCENARIO_REGISTRY._scenarios.items():
        if s_id == "cicd-compromise":
            engine.seed_topology(entry["graph_name"])
            engine.clone_graph(entry["graph_name"], entry["mirror_name"])
        else:
            engine.seed_from_manifest(
                entry["manifest"], entry["graph_name"], entry["mirror_name"]
            )


# Initialize scenarios
bootstrap_all_scenarios()


@app.get("/api/health")
def get_health():
    """Verify live FalkorDB connectivity and graph bootstrap status."""
    return {
        "status": "HEALTHY",
        "service": "TEZCATL Graph Engine",
        "prod_graph": engine.prod_name,
        "mirror_graph": engine.mirror_name,
        "active_scenarios": [s.id for s in SCENARIO_REGISTRY.list_scenarios()],
    }


@app.get("/api/scenarios", response_model=list[ScenarioSummary])
def list_available_scenarios():
    """Returns available security scenarios and their isolated graph identifiers."""
    return SCENARIO_REGISTRY.list_scenarios()


@app.post("/api/scenarios/import")
def import_scenario(manifest: SecurityTopologyManifest):
    """
    Imports and validates an external security-topology manifest into an isolated FalkorDB graph.
    Never overwrites prod_graph.
    """
    manifest_json = manifest.model_dump_json()
    if len(manifest_json.encode("utf-8")) > MAX_MANIFEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Manifest exceeds maximum allowed size of {MAX_MANIFEST_BYTES} bytes.",
        )

    entry = SCENARIO_REGISTRY.register_imported_scenario(manifest)
    res = engine.seed_from_manifest(manifest, entry["graph_name"], entry["mirror_name"])
    return {
        "status": "imported",
        "scenario_id": entry["id"],
        "name": entry["name"],
        "graph_name": entry["graph_name"],
        "mirror_name": entry["mirror_name"],
        "nodes": res["nodes"],
        "edges": res["edges"],
        "has_threat_model": manifest.scenario is not None,
    }


@app.get("/api/state")
def get_investigation_state(
    scenario_id: str = Query("cicd-compromise", description="Scenario ID to query"),
    source_id: Optional[str] = Query(None, description="Optional breach source override"),
):
    scen = SCENARIO_REGISTRY.get_scenario(scenario_id)
    if not scen:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")

    manifest: SecurityTopologyManifest = scen["manifest"]
    graph_name = scen["graph_name"]
    mirror_name = scen["mirror_name"]

    # 1. Fetch full topology from scenario's isolated graph
    topology, top_tel = engine.get_full_topology(graph_name)

    # 2. Case: No threat model supplied (Scenario B)
    if not manifest.scenario:
        default_source = source_id or (topology["nodes"][0]["id"] if topology["nodes"] else "none")
        return {
            "scenario_id": scenario_id,
            "scenario_name": scen["name"],
            "graph_name": graph_name,
            "source_id": default_source,
            "target_ids": [],
            "has_threat_model": False,
            "threat_model_message": "Architecture topology loaded. Security analysis requires an explicit threat model.",
            "topology": topology,
            "active_path_count": 0,
            "paths": [],
            "candidates": [],
            "cut_solution": {"optimal": None, "evaluated": []},
            "mirror_proof": None,
            "telemetry": [top_tel],
        }

    # 3. Case: Explicit threat model provided (Scenario A & C)
    sec = manifest.scenario
    active_source = source_id or sec.source_id
    target_ids = sec.target_ids
    max_depth = sec.max_depth

    paths, path_tel = engine.find_attack_paths(
        active_source, graph_name, target_ids=target_ids, max_depth=max_depth
    )
    candidates, calc_tels = engine.compute_centrality_and_blast_radius(
        paths, graph_name, scenario=sec
    )
    cut_solution = engine.solve_minimum_cut_set(active_source, paths, candidates)

    mirror_proof = None
    mirror_tels = []
    if cut_solution["optimal"]:
        mirror_proof = engine.verify_in_shadow_mirror(
            active_source,
            cut_solution["optimal"]["cut_nodes"],
            prod_graph=graph_name,
            mirror_graph=mirror_name,
            target_ids=target_ids,
            max_depth=max_depth,
        )
        mirror_tels = mirror_proof.get("telemetry", [])

    return {
        "scenario_id": scenario_id,
        "scenario_name": scen["name"],
        "graph_name": graph_name,
        "source_id": active_source,
        "target_ids": target_ids,
        "has_threat_model": True,
        "threat_model_message": None,
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
    scen = SCENARIO_REGISTRY.get_scenario(req.scenario_id)
    if not scen:
        raise HTTPException(status_code=404, detail=f"Scenario '{req.scenario_id}' not found.")

    target_ids = scen["manifest"].scenario.target_ids if scen["manifest"].scenario else None
    return engine.commit_containment(
        req.source_id,
        req.cut_nodes,
        req.blast_cost,
        graph_name=scen["graph_name"],
        target_ids=target_ids,
    )


@app.post("/api/mutate/bypass")
def mutate_bypass(req: SourceRequest):
    scen = SCENARIO_REGISTRY.get_scenario(req.scenario_id)
    if not scen:
        raise HTTPException(status_code=404, detail=f"Scenario '{req.scenario_id}' not found.")

    if req.scenario_id == "microservices-alternate":
        bypass_target = "vault-secrets"
    else:
        bypass_target = "release-controller"

    return engine.inject_bypass_edge(
        req.source_id, graph_name=scen["graph_name"], target_id=bypass_target
    )


@app.post("/api/reset")
def reset_scenario(scenario_id: str = Query("cicd-compromise", description="Scenario ID to reset")):
    scen = SCENARIO_REGISTRY.get_scenario(scenario_id)
    if not scen:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")

    if scenario_id == "cicd-compromise":
        engine.seed_topology(scen["graph_name"])
        engine.clone_graph(scen["graph_name"], scen["mirror_name"])
    else:
        engine.seed_from_manifest(scen["manifest"], scen["graph_name"], scen["mirror_name"])

    return {"status": "reset_complete", "scenario_id": scenario_id}


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
