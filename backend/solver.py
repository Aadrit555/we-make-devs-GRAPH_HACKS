"""
TEZCATL — Combinatorial Minimum-Cost Vertex-Cut Solver
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""
from itertools import combinations
from typing import Dict, Any, List, Optional
import math
import hashlib
import json
from backend.config import MAX_EXACT_CANDIDATES


def compute_plan_fingerprint(
    source_id: str,
    paths: List[Dict[str, Any]],
    candidates: List[Dict[str, Any]]
) -> str:
    """Generates a deterministic SHA-256 fingerprint of input paths and candidate costs."""
    canonical = {
        "source": source_id,
        "paths": sorted([
            f"{p['path_id']}:{p.get('target_id', '')}:{','.join(n['id'] for n in p.get('nodes', []))}"
            for p in paths
        ]),
        "candidates": sorted([
            f"{c['id']}:{c.get('blast_cost', 0)}:{','.join(sorted(c.get('impacted_services', [])))}"
            for c in candidates
        ]),
    }
    raw = json.dumps(canonical, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def solve_minimum_cut_set(
    source_id: str,
    paths: List[Dict[str, Any]],
    candidates: List[Dict[str, Any]],
    protected_nodes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Computes the optimal minimum-cost vertex cut that severs 100% of active attack paths.

    Exact supported optimization:
    Exhaustive search over all subsets of eligible mitigation candidates up to MAX_EXACT_CANDIDATES (18).
    If candidates exceed this cap, explicitly fails with an over-limit error rather than claiming false optimality.

    Tie-breaking:
    (total_cost, number_of_actions, lexicographically_sorted_action_ids)
    """
    if not paths:
        return {"optimal": None, "evaluated": [], "plan_fingerprint": None}

    protected_set = set(protected_nodes or [])
    protected_set.add(source_id)

    interior_sets = []
    all_interior_ids = set()
    for p in paths:
        p_nodes = p.get("nodes", [])
        if len(p_nodes) > 2:
            mids = {n["id"] for n in p_nodes[1:-1] if n["id"] not in protected_set}
        else:
            mids = set()
        interior_sets.append(mids)
        all_interior_ids.update(mids)

    # Validate and build candidate map
    cand_map: Dict[str, Dict[str, Any]] = {}
    for c in candidates:
        nid = c["id"]
        if nid in all_interior_ids and nid not in protected_set:
            cost = c.get("blast_cost")
            if cost is None or not isinstance(cost, (int, float)) or math.isnan(cost) or cost < 0:
                raise ValueError(f"Invalid blast cost for candidate '{nid}': {cost}")
            cand_map[nid] = c

    # Check candidate cap for exact solver
    if len(cand_map) > MAX_EXACT_CANDIDATES:
        return {
            "optimal": None,
            "evaluated": [],
            "error": f"Candidate set size ({len(cand_map)}) exceeds exact solver limit of {MAX_EXACT_CANDIDATES}.",
            "plan_fingerprint": None,
        }

    cand_keys = sorted(cand_map.keys())
    evaluated = []

    # Map shortest hop distance from source for each candidate (for reporting)
    min_hops: Dict[str, int] = {}
    for p in paths:
        for idx, n in enumerate(p.get("nodes", [])):
            nid = n["id"]
            if nid not in min_hops or idx < min_hops[nid]:
                min_hops[nid] = idx

    # Exhaustive search over all subset sizes 1 .. len(cand_keys)
    for r in range(1, len(cand_keys) + 1):
        for combo in combinations(cand_keys, r):
            combo_set = set(combo)
            severed_count = sum(1 for p_set in interior_sets if p_set & combo_set)
            total_cost = sum(cand_map[nid]["blast_cost"] for nid in combo)
            services = sorted({svc for nid in combo for svc in cand_map[nid].get("impacted_services", [])})
            proximity = sum(min_hops.get(nid, 99) for nid in combo) / len(combo)
            is_complete = severed_count == len(paths)

            evaluated.append({
                "cut_nodes": list(combo),
                "cut_names": [cand_map[nid].get("name", nid) for nid in combo],
                "blast_cost": int(total_cost),
                "paths_severed": severed_count,
                "total_paths": len(paths),
                "complete_cut": is_complete,
                "impacted_services": services,
                "proximity": round(proximity, 2),
            })

    # Exact deterministic sorting:
    # 1. Complete cut (True first)
    # 2. Minimal total blast cost
    # 3. Minimal number of actions (cardinality)
    # 4. Minimal proximity (average hop distance from breach origin, containing earlier)
    # 5. Lexicographical action IDs for deterministic tie-breaking
    evaluated.sort(key=lambda x: (
        not x["complete_cut"],
        x["blast_cost"],
        len(x["cut_nodes"]),
        x.get("proximity", 999.0),
        sorted(x["cut_nodes"])
    ))

    optimal = next((item for item in evaluated if item["complete_cut"]), None)
    plan_fingerprint = compute_plan_fingerprint(source_id, paths, candidates)
    if optimal:
        optimal["plan_fingerprint"] = plan_fingerprint

    return {
        "optimal": optimal,
        "evaluated": evaluated[:10],
        "plan_fingerprint": plan_fingerprint,
        "infeasible": optimal is None,
    }
