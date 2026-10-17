"""
TEZCATL — Graph-Native Breach Containment Agent on FalkorDB
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""
import time
import hashlib
import json
from typing import Any, List, Dict, Optional, Tuple
from falkordb import FalkorDB
from backend.config import (
    FALKORDB_HOST,
    FALKORDB_PORT,
    PROD_GRAPH,
    MIRROR_GRAPH,
    MAX_TRAVERSAL_DEPTH,
)
from backend.models import (
    ALLOWED_RELATIONSHIP_TYPES,
    SecurityTopologyManifest,
    SecurityScenario,
)
from backend.seed import seed_graph
from backend.solver import solve_minimum_cut_set


class TezcatlGraphEngine:
    def __init__(
        self,
        host: str = FALKORDB_HOST,
        port: int = FALKORDB_PORT,
        prod_name: Optional[str] = None,
        mirror_name: Optional[str] = None,
    ):
        self.db = FalkorDB(host=host, port=port)
        self.prod_name = prod_name or PROD_GRAPH
        self.mirror_name = mirror_name or MIRROR_GRAPH
        self.ensure_seeded()

    def _run(
        self, graph_name: str, cypher: str, params: Optional[Dict[str, Any]] = None
    ) -> Tuple[List[Any], Dict[str, Any]]:
        graph = self.db.select_graph(graph_name)
        t0 = time.perf_counter()
        res = graph.query(cypher, params=params or {})
        dt_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        telemetry = {
            "graph": graph_name,
            "cypher": " ".join(line.strip() for line in cypher.strip().splitlines()),
            "params": params or {},
            "execution_ms": round(float(getattr(res, "run_time_ms", dt_ms) or dt_ms), 2),
            "rows": len(res.result_set) if res.result_set else 0,
        }
        return (res.result_set or []), telemetry

    def ensure_seeded(self) -> None:
        """Ensures the canonical demo graph is seeded."""
        rows, _ = self._run(self.prod_name, "MATCH (n:Entity) RETURN count(n)")
        if not rows or rows[0][0] == 0:
            self.seed_topology(self.prod_name)
            self.clone_graph(self.prod_name, self.mirror_name)

    def seed_topology(self, target_graph: str) -> Dict[str, Any]:
        """Seeds canonical CI/CD baseline topology."""
        return seed_graph(self.db, target_graph)

    def seed_from_manifest(
        self, manifest: SecurityTopologyManifest, target_graph: str, mirror_graph: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Populates an isolated FalkorDB graph strictly from a validated SecurityTopologyManifest.
        Preserves relationship semantics and does not invent missing nodes or permissions.
        """
        g = self.db.select_graph(target_graph)
        g.query("MATCH (n) DETACH DELETE n")

        # 1. Insert Entity nodes
        for node in manifest.nodes:
            g.query(
                "CREATE (:Entity {id: $id, name: $name, kind: $kind, criticality: $criticality, status: $status})",
                params={
                    "id": node.id,
                    "name": node.name,
                    "kind": node.kind,
                    "criticality": node.criticality,
                    "status": node.status,
                },
            )

        # 2. Insert Edges with validated relationship types from allowlist
        for edge in manifest.edges:
            rel_type = edge.type
            if rel_type not in ALLOWED_RELATIONSHIP_TYPES:
                raise ValueError(f"Unapproved relationship type: '{rel_type}'")

            mech = edge.metadata.get("mechanism", rel_type)
            ev = edge.metadata.get("evidence_id", edge.id)
            is_active = edge.metadata.get("active", True)

            cypher = f"""
            MATCH (a:Entity {{id: $src}}), (b:Entity {{id: $dst}})
            CREATE (a)-[:{rel_type} {{mechanism: $mech, evidence_id: $ev, active: $active, id: $eid}}]->(b)
            """
            g.query(
                cypher,
                params={
                    "src": edge.source,
                    "dst": edge.target,
                    "mech": mech,
                    "ev": ev,
                    "active": is_active,
                    "eid": edge.id,
                },
            )

        # 3. If scenario contains modeled mitigations, create Service nodes and DEPENDS_ON relations
        # so native blast radius graph queries work seamlessly
        if manifest.scenario and manifest.scenario.eligible_mitigations:
            for em in manifest.scenario.eligible_mitigations:
                svcs = em.impacted_services or [f"svc-{em.node_id}"]
                weight_per_svc = max(1, em.blast_cost // max(len(svcs), 1))
                for svc_name in svcs:
                    svc_id = f"svc-{svc_name}".lower().replace(" ", "-")
                    g.query(
                        "MERGE (s:Service {id: $id}) ON CREATE SET s.name = $name, s.revenue_weight = $w",
                        params={"id": svc_id, "name": svc_name, "w": weight_per_svc},
                    )
                    g.query(
                        """
                        MATCH (s:Service {id: $svc_id}), (e:Entity {id: $ent_id})
                        MERGE (s)-[:DEPENDS_ON]->(e)
                        """,
                        params={"svc_id": svc_id, "ent_id": em.node_id},
                    )

        if mirror_graph:
            self.clone_graph(target_graph, mirror_graph)

        return {
            "graph": target_graph,
            "nodes": len(manifest.nodes),
            "edges": len(manifest.edges),
        }

    def clone_graph(self, src_graph: str, dst_graph: str) -> Dict[str, Any]:
        """Clones all Entity nodes, Service nodes, and all approved relationship types."""
        dst = self.db.select_graph(dst_graph)
        dst.query("MATCH (n) DETACH DELETE n")

        ents, _ = self._run(
            src_graph,
            "MATCH (e:Entity) RETURN e.id, e.name, e.kind, e.criticality, e.status",
        )
        for r in ents:
            dst.query(
                "CREATE (:Entity {id: $id, name: $name, kind: $kind, criticality: $crit, status: $status})",
                params={"id": r[0], "name": r[1], "kind": r[2], "crit": r[3], "status": r[4]},
            )

        svcs, _ = self._run(
            src_graph,
            "MATCH (s:Service) RETURN s.id, s.name, s.revenue_weight",
        )
        for r in svcs:
            dst.query(
                "CREATE (:Service {id: $id, name: $name, revenue_weight: $w})",
                params={"id": r[0], "name": r[1], "w": r[2]},
            )

        cloned_edges_count = 0
        for rel_type in ALLOWED_RELATIONSHIP_TYPES:
            query = f"MATCH (a:Entity)-[r:{rel_type}]->(b:Entity) RETURN a.id, b.id, r.mechanism, r.evidence_id, coalesce(r.active, true)"
            steps, _ = self._run(src_graph, query)
            for r in steps:
                dst.query(
                    f"""
                    MATCH (a:Entity {{id: $src}}), (b:Entity {{id: $dst}})
                    CREATE (a)-[:{rel_type} {{mechanism: $mech, evidence_id: $ev, active: $active}}]->(b)
                    """,
                    params={"src": r[0], "dst": r[1], "mech": r[2], "ev": r[3], "active": r[4]},
                )
                cloned_edges_count += 1

        deps, _ = self._run(
            src_graph,
            "MATCH (s:Service)-[:DEPENDS_ON]->(e:Entity) RETURN s.id, e.id",
        )
        for r in deps:
            dst.query(
                "MATCH (s:Service {id: $svc}), (e:Entity {id: $ent}) CREATE (s)-[:DEPENDS_ON]->(e)",
                params={"svc": r[0], "ent": r[1]},
            )

        return {"cloned_entities": len(ents), "cloned_edges": cloned_edges_count}

    def clone_prod_to_mirror(self) -> Dict[str, Any]:
        return self.clone_graph(self.prod_name, self.mirror_name)

    def get_full_topology(self, graph_name: Optional[str] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        target = graph_name or self.prod_name
        n_rows, n_tel = self._run(
            target,
            "MATCH (e:Entity) RETURN e.id, e.name, e.kind, e.criticality, e.status ORDER BY e.id",
        )
        e_rows, _ = self._run(
            target,
            "MATCH (a:Entity)-[r]->(b:Entity) RETURN a.id, b.id, type(r), r.mechanism, r.evidence_id, coalesce(r.active, true) ORDER BY a.id, b.id",
        )
        nodes = [{"id": r[0], "name": r[1], "kind": r[2], "criticality": r[3], "status": r[4]} for r in n_rows]
        edges = [
            {
                "source": r[0],
                "target": r[1],
                "type": r[2],
                "mechanism": r[3] or r[2],
                "evidence_id": r[4] or "",
                "active": bool(r[5]),
            }
            for r in e_rows
        ]
        return {"nodes": nodes, "edges": edges}, n_tel

    def find_attack_paths(
        self,
        source_id: str,
        graph_name: Optional[str] = None,
        target_ids: Optional[List[str]] = None,
        max_depth: int = MAX_TRAVERSAL_DEPTH,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        target = graph_name or self.prod_name
        depth = min(max_depth, MAX_TRAVERSAL_DEPTH)

        if target_ids and len(target_ids) > 0:
            cypher = f"""
            MATCH (src:Entity {{id: $source_id}}), (target:Entity)
            WHERE target.id IN $target_ids
            MATCH p = (src)-[:ATTACK_STEP*1..{depth}]->(target)
            WHERE ALL(r IN relationships(p) WHERE coalesce(r.active, true) = true)
              AND NONE(n IN nodes(p) WHERE n.status = 'isolated')
            RETURN target.id AS target_id,
                   length(p) AS hops,
                   [n IN nodes(p) | {{id: n.id, name: n.name, kind: n.kind}}] AS nodes,
                   [r IN relationships(p) | {{mechanism: r.mechanism, evidence_id: r.evidence_id}}] AS edges
            ORDER BY hops ASC
            """
            params = {"source_id": source_id, "target_ids": target_ids}
        else:
            cypher = f"""
            MATCH (src:Entity {{id: $source_id}}), (target:Entity {{criticality: $crit}})
            MATCH p = (src)-[:ATTACK_STEP*1..{depth}]->(target)
            WHERE ALL(r IN relationships(p) WHERE coalesce(r.active, true) = true)
              AND NONE(n IN nodes(p) WHERE n.status = 'isolated')
            RETURN target.id AS target_id,
                   length(p) AS hops,
                   [n IN nodes(p) | {{id: n.id, name: n.name, kind: n.kind}}] AS nodes,
                   [r IN relationships(p) | {{mechanism: r.mechanism, evidence_id: r.evidence_id}}] AS edges
            ORDER BY hops ASC
            """
            params = {"source_id": source_id, "crit": "crown_jewel"}

        rows, tel = self._run(target, cypher, params)
        paths = []
        for idx, row in enumerate(rows):
            paths.append({
                "path_id": f"PATH-0{idx + 1}",
                "target_id": row[0],
                "hops": row[1],
                "nodes": row[2],
                "edges": row[3],
            })
        return paths, tel

    def compute_centrality_and_blast_radius(
        self,
        paths: List[Dict[str, Any]],
        graph_name: Optional[str] = None,
        scenario: Optional[SecurityScenario] = None,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        target = graph_name or self.prod_name
        telemetries = []
        centrality_scores: Dict[str, float] = {}

        try:
            c_rows, c_tel = self._run(
                target,
                "CALL algo.betweenness({nodeLabels: ['Entity'], relationshipTypes: ['ATTACK_STEP']}) YIELD node, score RETURN node.id, score ORDER BY score DESC",
            )
            telemetries.append(c_tel)
            for r in c_rows:
                centrality_scores[r[0]] = round(float(r[1]), 3)
        except Exception:
            # Deterministic topological path betweenness calculation
            total_p = max(len(paths), 1)
            for p in paths:
                for n in p["nodes"][1:-1]:
                    centrality_scores[n["id"]] = round(centrality_scores.get(n["id"], 0.0) + (1.0 / total_p), 3)

        b_cypher = """
        MATCH (e:Entity)
        WHERE e.criticality <> 'crown_jewel'
        OPTIONAL MATCH (s:Service)-[:DEPENDS_ON*1..4]->(e)
        WITH e, collect(DISTINCT s) AS svcs
        WITH e, [x IN svcs | x.name] AS svc_names, reduce(tot = 0, x IN svcs | tot + x.revenue_weight) AS cost
        RETURN e.id AS id,
               e.name AS name,
               e.kind AS kind,
               e.status AS status,
               cost AS blast_cost,
               svc_names AS impacted_services
        ORDER BY blast_cost ASC
        """
        b_rows, b_tel = self._run(target, b_cypher)
        telemetries.append(b_tel)

        # Build candidate map from graph
        cand_map: Dict[str, Dict[str, Any]] = {}
        for row in b_rows:
            nid = row[0]
            services_val = row[5] if isinstance(row[5], list) else []
            cand_map[nid] = {
                "id": nid,
                "name": row[1],
                "kind": row[2],
                "status": row[3],
                "blast_cost": int(row[4] or 0),
                "impacted_services": [s for s in services_val if s],
                "centrality": centrality_scores.get(nid, 0.0),
            }

        # If scenario provides explicit modeled mitigations, enforce modeled costs with provenance
        if scenario and scenario.eligible_mitigations:
            for em in scenario.eligible_mitigations:
                if em.node_id in cand_map:
                    cand_map[em.node_id]["blast_cost"] = em.blast_cost
                    if em.impacted_services:
                        cand_map[em.node_id]["impacted_services"] = em.impacted_services

        candidates = list(cand_map.values())
        return candidates, telemetries

    def solve_minimum_cut_set(
        self, source_id: str, paths: List[Dict[str, Any]], candidates: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        return solve_minimum_cut_set(source_id, paths, candidates)

    def verify_in_shadow_mirror(
        self,
        source_id: str,
        cut_nodes: List[str],
        prod_graph: Optional[str] = None,
        mirror_graph: Optional[str] = None,
        target_ids: Optional[List[str]] = None,
        max_depth: int = MAX_TRAVERSAL_DEPTH,
    ) -> Dict[str, Any]:
        p_graph = prod_graph or self.prod_name
        m_graph = mirror_graph or self.mirror_name

        self.clone_graph(p_graph, m_graph)
        isolate_cypher = """
        MATCH (e:Entity)
        WHERE e.id IN $cut_nodes
        SET e.status = 'isolated'
        RETURN count(e)
        """
        _, mut_tel = self._run(m_graph, isolate_cypher, {"cut_nodes": cut_nodes})
        mirror_paths, ver_tel = self.find_attack_paths(
            source_id, graph_name=m_graph, target_ids=target_ids, max_depth=max_depth
        )
        return {
            "mirror_graph": m_graph,
            "isolated_nodes": cut_nodes,
            "remaining_paths": len(mirror_paths),
            "verified_safe": len(mirror_paths) == 0,
            "telemetry": [mut_tel, ver_tel],
        }

    def commit_containment(
        self,
        source_id: str,
        cut_nodes: List[str],
        blast_cost: int,
        graph_name: Optional[str] = None,
        target_ids: Optional[List[str]] = None,
        max_depth: int = MAX_TRAVERSAL_DEPTH,
    ) -> Dict[str, Any]:
        target = graph_name or self.prod_name
        pre_paths, _ = self.find_attack_paths(
            source_id, graph_name=target, target_ids=target_ids, max_depth=max_depth
        )
        isolate_cypher = """
        MATCH (e:Entity)
        WHERE e.id IN $cut_nodes
        SET e.status = 'isolated'
        RETURN collect(e.id)
        """
        _, mut_tel = self._run(target, isolate_cypher, {"cut_nodes": cut_nodes})
        post_paths, ver_tel = self.find_attack_paths(
            source_id, graph_name=target, target_ids=target_ids, max_depth=max_depth
        )

        payload = {
            "source_id": source_id,
            "severed_nodes": cut_nodes,
            "pre_paths": len(pre_paths),
            "post_paths": len(post_paths),
            "blast_cost": blast_cost,
            "timestamp": int(time.time()),
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return {
            **payload,
            "sha256_receipt": digest,
            "telemetry": [mut_tel, ver_tel],
        }

    def inject_bypass_edge(
        self,
        source_id: str,
        graph_name: Optional[str] = None,
        target_id: str = "release-controller",
    ) -> Dict[str, Any]:
        target = graph_name or self.prod_name
        cypher = """
        MATCH (src:Entity {id: $source_id}), (rc:Entity {id: $target_id})
        MERGE (src)-[r:ATTACK_STEP {mechanism: $mech, evidence_id: $ev}]->(rc)
        SET r.active = true
        RETURN type(r)
        """
        _, tel = self._run(
            target,
            cypher,
            {
                "source_id": source_id,
                "target_id": target_id,
                "mech": "SHADOW_SSH_SOCKET",
                "ev": "EV-999",
            },
        )
        return {"status": "bypass_injected", "telemetry": tel}
