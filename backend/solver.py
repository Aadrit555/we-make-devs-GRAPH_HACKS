"""
TEZCATL — Combinatorial Minimum-Cost Vertex-Cut Solver
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""
from itertools import combinations
from typing import Dict, Any, List, Optional


def solve_minimum_cut_set(
    source_id: str,
    paths: List[Dict[str, Any]],
    candidates: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Computes the optimal minimum-cost vertex cut that severs 100% of active attack paths.
    
    Tie-breaking:
    When multiple cuts share the minimal blast_cost and cardinality, cuts with lower average
    hop distance from the breach source (proximity) are prioritized deterministically.
    """
    if not paths:
        return {"optimal": None, "evaluated": []}

    interior_sets = []
    all_interior_ids = set()
    for p in paths:
        mids = {n["id"] for n in p["nodes"][1:-1]}
        interior_sets.append(mids)
        all_interior_ids.update(mids)

    cand_map = {c["id"]: c for c in candidates if c["id"] in all_interior_ids and c["id"] != source_id}
    evaluated = []

    # Map shortest hop distance from source for each candidate
    min_hops: Dict[str, int] = {}
    for p in paths:
        for idx, n in enumerate(p["nodes"]):
            nid = n["id"]
            if nid not in min_hops or idx < min_hops[nid]:
                min_hops[nid] = idx

    for r in range(1, min(4, len(cand_map) + 1)):
        for combo in combinations(cand_map.keys(), r):
            combo_set = set(combo)
            severed_count = sum(1 for p_set in interior_sets if p_set & combo_set)
            total_cost = sum(cand_map[nid]["blast_cost"] for nid in combo)
            services = sorted({svc for nid in combo for svc in cand_map[nid]["impacted_services"]})
            proximity = sum(min_hops.get(nid, 99) for nid in combo) / len(combo)
            evaluated.append({
                "cut_nodes": list(combo),
                "cut_names": [cand_map[nid]["name"] for nid in combo],
                "blast_cost": total_cost,
                "paths_severed": severed_count,
                "total_paths": len(paths),
                "complete_cut": severed_count == len(paths),
                "impacted_services": services,
                "proximity": proximity,
            })

    evaluated.sort(key=lambda x: (not x["complete_cut"], x["blast_cost"], len(x["cut_nodes"]), x["proximity"]))
    optimal = next((item for item in evaluated if item["complete_cut"]), None)
    return {"optimal": optimal, "evaluated": evaluated[:8]}

