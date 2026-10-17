"""
TEZCATL — Graph-Native Breach Containment Agent on FalkorDB
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""
import time
import hashlib
import json
from typing import Any
from falkordb import FalkorDB
from backend.config import (
    FALKORDB_HOST,
    FALKORDB_PORT,
    PROD_GRAPH,
    MIRROR_GRAPH,
    DB_STARTUP_RETRIES,
    DB_RETRY_INTERVAL,
)
from backend.seed import seed_graph
from backend.solver import solve_minimum_cut_set


class TezcatlGraphEngine:
    def __init__(
        self,
        host: str = FALKORDB_HOST,
        port: int = FALKORDB_PORT,
        prod_graph: str = PROD_GRAPH,
        mirror_graph: str = MIRROR_GRAPH,
        auto_connect: bool = True,
    ):
        self.host = host
        self.port = port
        self.prod_name = prod_graph
        self.mirror_name = mirror_graph
        self.db = FalkorDB(host=self.host, port=self.port)
        if auto_connect:
            self.connect_with_retries()
            self.ensure_seeded()

    def connect_with_retries(self, retries: int = DB_STARTUP_RETRIES, interval: float = DB_RETRY_INTERVAL) -> None:
        last_err = None
        for attempt in range(1, retries + 1):
            try:
                self.check_health()
                return
            except Exception as err:
                last_err = err
                time.sleep(interval)
        raise RuntimeError(
            f"Critical startup failure: Unable to establish ready connection to FalkorDB at {self.host}:{self.port} after {retries} attempts: {last_err}"
        )

    def check_health(self) -> dict[str, Any]:
        t0 = time.perf_counter()
        self._run(self.prod_name, "RETURN 1")
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        ents, _ = self._run(self.prod_name, "MATCH (e:Entity) RETURN count(e)")
        svcs, _ = self._run(self.prod_name, "MATCH (s:Service) RETURN count(s)")
        return {
            "status": "HEALTHY",
            "database": "FalkorDB Connected",
            "host": self.host,
            "port": self.port,
            "prod_graph": self.prod_name,
            "mirror_graph": self.mirror_name,
            "entity_count": ents[0][0] if ents else 0,
            "service_count": svcs[0][0] if svcs else 0,
            "latency_ms": latency_ms,
        }

    def _run(self, graph_name: str, cypher: str, params: dict[str, Any] | None = None) -> tuple[list[Any], dict[str, Any]]:
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
        rows, _ = self._run(self.prod_name, "MATCH (n:Entity) RETURN count(n)")
        if not rows or rows[0][0] == 0:
            self.seed_topology(self.prod_name)
            self.clone_prod_to_mirror()

    def seed_topology(self, target_graph: str) -> dict[str, Any]:
        return seed_graph(self.db, target_graph)

    def clone_prod_to_mirror(self) -> dict[str, Any]:
        """Reads live nodes and edges from prod_graph and clones them into tezcatl_mirror."""
        mirror = self.db.select_graph(self.mirror_name)
        mirror.query("MATCH (n) DETACH DELETE n")

        ents, _ = self._run(
            self.prod_name,
            "MATCH (e:Entity) RETURN e.id, e.name, e.kind, e.criticality, e.status",
        )
        for r in ents:
            mirror.query(
                "CREATE (:Entity {id: $id, name: $name, kind: $kind, criticality: $crit, status: $status})",
                params={"id": r[0], "name": r[1], "kind": r[2], "crit": r[3], "status": r[4]},
            )

        svcs, _ = self._run(
            self.prod_name,
            "MATCH (s:Service) RETURN s.id, s.name, s.revenue_weight",
        )
        for r in svcs:
            mirror.query(
                "CREATE (:Service {id: $id, name: $name, revenue_weight: $w})",
                params={"id": r[0], "name": r[1], "w": r[2]},
            )

        steps, _ = self._run(
            self.prod_name,
            "MATCH (a:Entity)-[r:ATTACK_STEP]->(b:Entity) RETURN a.id, b.id, r.mechanism, r.evidence_id, r.active",
        )
        for r in steps:
            mirror.query(
                """
                MATCH (a:Entity {id: $src}), (b:Entity {id: $dst})
                CREATE (a)-[:ATTACK_STEP {mechanism: $mech, evidence_id: $ev, active: $active}]->(b)
                """,
                params={"src": r[0], "dst": r[1], "mech": r[2], "ev": r[3], "active": r[4]},
            )

        deps, _ = self._run(
            self.prod_name,
            "MATCH (s:Service)-[:DEPENDS_ON]->(e:Entity) RETURN s.id, e.id",
        )
        for r in deps:
            mirror.query(
                "MATCH (s:Service {id: $svc}), (e:Entity {id: $ent}) CREATE (s)-[:DEPENDS_ON]->(e)",
                params={"svc": r[0], "ent": r[1]},
            )

        return {"cloned_entities": len(ents), "cloned_attack_edges": len(steps)}

    def get_full_topology(self, graph_name: str = PROD_GRAPH) -> tuple[dict[str, Any], dict[str, Any]]:
        n_rows, n_tel = self._run(
            graph_name,
            "MATCH (e:Entity) RETURN e.id, e.name, e.kind, e.criticality, e.status ORDER BY e.id",
        )
        e_rows, _ = self._run(
            graph_name,
            "MATCH (a:Entity)-[r:ATTACK_STEP]->(b:Entity) WHERE r.active = true RETURN a.id, b.id, r.mechanism, r.evidence_id",
        )
        nodes = [{"id": r[0], "name": r[1], "kind": r[2], "criticality": r[3], "status": r[4]} for r in n_rows]
        edges = [{"source": r[0], "target": r[1], "mechanism": r[2], "evidence_id": r[3]} for r in e_rows]
        return {"nodes": nodes, "edges": edges}, n_tel

    def find_attack_paths(self, source_id: str, graph_name: str = PROD_GRAPH) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        cypher = """
        MATCH (src:Entity {id: $source_id}), (target:Entity {criticality: $crit})
        MATCH p = (src)-[:ATTACK_STEP*1..8]->(target)
        WHERE ALL(r IN relationships(p) WHERE r.active = true)
          AND NONE(n IN nodes(p) WHERE n.status = 'isolated')
        RETURN target.id AS target_id,
               length(p) AS hops,
               [n IN nodes(p) | {id: n.id, name: n.name, kind: n.kind}] AS nodes,
               [r IN relationships(p) | {mechanism: r.mechanism, evidence_id: r.evidence_id}] AS edges
        ORDER BY hops ASC
        """
        rows, tel = self._run(graph_name, cypher, {"source_id": source_id, "crit": "crown_jewel"})
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

    def compute_centrality_and_blast_radius(self, paths: list[dict[str, Any]], graph_name: str = PROD_GRAPH) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        telemetries = []
        centrality_scores: dict[str, float] = {}
        c_rows, c_tel = self._run(
            graph_name,
            "CALL algo.betweenness({nodeLabels: ['Entity'], relationshipTypes: ['ATTACK_STEP']}) YIELD node, score RETURN node.id, score ORDER BY score DESC",
        )
        telemetries.append(c_tel)
        for r in c_rows:
            centrality_scores[r[0]] = round(float(r[1]), 3)

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
        b_rows, b_tel = self._run(graph_name, b_cypher)
        telemetries.append(b_tel)

        candidates = []
        for row in b_rows:
            nid = row[0]
            services_val = row[5] if isinstance(row[5], list) else []
            candidates.append({
                "id": nid,
                "name": row[1],
                "kind": row[2],
                "status": row[3],
                "blast_cost": int(row[4] or 0),
                "impacted_services": [s for s in services_val if s],
                "centrality": centrality_scores.get(nid, 0.0),
            })
        return candidates, telemetries

    def solve_minimum_cut_set(self, source_id: str, paths: list[dict[str, Any]], candidates: list[dict[str, Any]]) -> dict[str, Any]:
        return solve_minimum_cut_set(source_id, paths, candidates)

    def verify_in_shadow_mirror(self, source_id: str, cut_nodes: list[str]) -> dict[str, Any]:
        self.clone_prod_to_mirror()
        isolate_cypher = """
        MATCH (e:Entity)
        WHERE e.id IN $cut_nodes
        SET e.status = 'isolated'
        RETURN count(e)
        """
        _, mut_tel = self._run(self.mirror_name, isolate_cypher, {"cut_nodes": cut_nodes})
        mirror_paths, ver_tel = self.find_attack_paths(source_id, graph_name=self.mirror_name)
        return {
            "mirror_graph": self.mirror_name,
            "isolated_nodes": cut_nodes,
            "remaining_paths": len(mirror_paths),
            "verified_safe": len(mirror_paths) == 0,
            "telemetry": [mut_tel, ver_tel],
        }

    def commit_containment(
        self,
        source_id: str,
        caller_cut_nodes: list[str] | None = None,
        caller_blast_cost: int | None = None,
    ) -> dict[str, Any]:
        # 1. Fresh pre-action path discovery
        pre_paths, _ = self.find_attack_paths(source_id, graph_name=self.prod_name)
        if not pre_paths:
            raise ValueError(f"No active attack paths detected from source '{source_id}' — containment already applied or unnecessary.")

        # 2. Server-side candidate and blast radius evaluation
        candidates, _ = self.compute_centrality_and_blast_radius(pre_paths, graph_name=self.prod_name)

        # 3. Server-side minimum-cost vertex-cut recomputation
        solution = self.solve_minimum_cut_set(source_id, pre_paths, candidates)
        optimal = solution.get("optimal")
        if not optimal or not optimal.get("complete_cut"):
            raise RuntimeError(f"Server-side solver could not compute a complete cut to sever all paths from '{source_id}'.")

        # Server-side verified cut set and true blast cost
        server_cut_nodes = optimal["cut_nodes"]
        server_blast_cost = optimal["blast_cost"]

        # 4. Apply verified containment to prod_graph
        isolate_cypher = """
        MATCH (e:Entity)
        WHERE e.id IN $cut_nodes
        SET e.status = 'isolated'
        RETURN collect(e.id)
        """
        _, mut_tel = self._run(self.prod_name, isolate_cypher, {"cut_nodes": server_cut_nodes})

        # 5. FRESH POST-ACTION QUERY to mathematically verify reachability is 0
        post_paths, ver_tel = self.find_attack_paths(source_id, graph_name=self.prod_name)
        if len(post_paths) > 0:
            raise RuntimeError(
                f"Containment verification failed: {len(post_paths)} active attack paths remain after severing {server_cut_nodes}."
            )

        payload = {
            "source_id": source_id,
            "severed_nodes": server_cut_nodes,
            "pre_paths": len(pre_paths),
            "post_paths": len(post_paths),
            "blast_cost": server_blast_cost,
            "status": "CONTAINED_AND_VERIFIED",
            "timestamp": int(time.time()),
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return {
            **payload,
            "sha256_receipt": digest,
            "telemetry": [mut_tel, ver_tel],
        }

    def inject_bypass_edge(self, source_id: str) -> dict[str, Any]:
        cypher = """
        MATCH (src:Entity {id: $source_id}), (rc:Entity {id: $target_id})
        MERGE (src)-[r:ATTACK_STEP {mechanism: $mech, evidence_id: $ev}]->(rc)
        SET r.active = true
        RETURN type(r)
        """
        _, tel = self._run(
            self.prod_name,
            cypher,
            {
                "source_id": source_id,
                "target_id": "release-controller",
                "mech": "SHADOW_SSH_SOCKET",
                "ev": "EV-999",
            },
        )
        return {"status": "bypass_injected", "telemetry": tel}
