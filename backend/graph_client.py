"""
TEZCATL — Graph-Native Breach Containment Agent on FalkorDB
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""
import time
import hashlib
import json
from itertools import combinations
from typing import Any
from falkordb import FalkorDB
from backend.config import FALKORDB_HOST, FALKORDB_PORT, PROD_GRAPH, MIRROR_GRAPH


class TezcatlGraphEngine:
    def __init__(self, host: str = FALKORDB_HOST, port: int = FALKORDB_PORT):
        self.db = FalkorDB(host=host, port=port)
        self.prod_name = PROD_GRAPH
        self.mirror_name = MIRROR_GRAPH
        self.ensure_seeded()

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
        g = self.db.select_graph(target_graph)
        g.query("MATCH (n) DETACH DELETE n")

        entities = [
            {"id": "ci-runner-07", "name": "CI Build Runner 07", "kind": "workload", "criticality": "standard", "status": "active"},
            {"id": "staging-worker-02", "name": "Staging Worker 02", "kind": "workload", "criticality": "standard", "status": "active"},
            {"id": "tok-deploy-alpha", "name": "CI Deploy Token Alpha", "kind": "credential", "criticality": "high", "status": "active"},
            {"id": "tok-artifact-rw", "name": "Artifact Registry RW Token", "kind": "credential", "criticality": "high", "status": "active"},
            {"id": "role-cloud-deployer", "name": "IAM Cloud Deployer Role", "kind": "role", "criticality": "high", "status": "active"},
            {"id": "pkg-registry-core", "name": "Internal Package Registry", "kind": "workload", "criticality": "high", "status": "active"},
            {"id": "release-controller", "name": "Prod Release Controller", "kind": "workload", "criticality": "bottleneck", "status": "active"},
            {"id": "prod-signing-key", "name": "Root Production Signing Key", "kind": "secret", "criticality": "crown_jewel", "status": "active"},
        ]
        for ent in entities:
            g.query(
                "CREATE (:Entity {id: $id, name: $name, kind: $kind, criticality: $criticality, status: $status})",
                params=ent,
            )

        services = [
            {"id": "svc-ci-telemetry", "name": "CI Log Aggregator", "weight": 2},
            {"id": "svc-artifact-sync", "name": "Artifact Mirror Sync", "weight": 3},
            {"id": "svc-checkout-api", "name": "Global Checkout API", "weight": 5},
            {"id": "svc-release-pipe", "name": "Zero-Downtime Release Train", "weight": 5},
            {"id": "svc-auth-gateway", "name": "Edge OIDC Gateway", "weight": 4},
        ]
        for svc in services:
            g.query(
                "CREATE (:Service {id: $id, name: $name, revenue_weight: $weight})",
                params=svc,
            )

        attack_steps = [
            {"src": "ci-runner-07", "dst": "tok-deploy-alpha", "mech": "ENV_MEM_DUMP", "ev": "EV-101"},
            {"src": "tok-deploy-alpha", "dst": "role-cloud-deployer", "mech": "STS_ASSUME_ROLE", "ev": "EV-102"},
            {"src": "role-cloud-deployer", "dst": "release-controller", "mech": "K8S_EXEC_PRIV", "ev": "EV-103"},
            {"src": "ci-runner-07", "dst": "tok-artifact-rw", "mech": "CACHE_POISON_TOKEN", "ev": "EV-104"},
            {"src": "tok-artifact-rw", "dst": "pkg-registry-core", "mech": "MALICIOUS_WHEEL_PUSH", "ev": "EV-105"},
            {"src": "pkg-registry-core", "dst": "release-controller", "mech": "AUTO_BUILD_TRIGGER", "ev": "EV-106"},
            {"src": "staging-worker-02", "dst": "tok-artifact-rw", "mech": "SHARED_MOUNT_LEAK", "ev": "EV-107"},
            {"src": "release-controller", "dst": "prod-signing-key", "mech": "KMS_DECRYPT_GRANT", "ev": "EV-108"},
        ]
        for step in attack_steps:
            g.query(
                """
                MATCH (a:Entity {id: $src}), (b:Entity {id: $dst})
                CREATE (a)-[:ATTACK_STEP {mechanism: $mech, evidence_id: $ev, active: true}]->(b)
                """,
                params=step,
            )

        dependencies = [
            {"svc": "svc-ci-telemetry", "ent": "tok-deploy-alpha"},
            {"svc": "svc-artifact-sync", "ent": "tok-artifact-rw"},
            {"svc": "svc-artifact-sync", "ent": "pkg-registry-core"},
            {"svc": "svc-release-pipe", "ent": "role-cloud-deployer"},
            {"svc": "svc-checkout-api", "ent": "release-controller"},
            {"svc": "svc-release-pipe", "ent": "release-controller"},
            {"svc": "svc-auth-gateway", "ent": "release-controller"},
        ]
        for dep in dependencies:
            g.query(
                """
                MATCH (s:Service {id: $svc}), (e:Entity {id: $ent})
                CREATE (s)-[:DEPENDS_ON]->(e)
                """,
                params=dep,
            )

        return {"seeded_graph": target_graph, "entities": len(entities), "services": len(services)}

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
        try:
            c_rows, c_tel = self._run(
                graph_name,
                "CALL algo.betweenness({nodeLabels: ['Entity'], relationshipTypes: ['ATTACK_STEP']}) YIELD node, score RETURN node.id, score ORDER BY score DESC",
            )
            telemetries.append(c_tel)
            for r in c_rows:
                centrality_scores[r[0]] = round(float(r[1]), 3)
        except Exception:
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

        min_hops: dict[str, int] = {}
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

    def commit_containment(self, source_id: str, cut_nodes: list[str], blast_cost: int) -> dict[str, Any]:
        pre_paths, _ = self.find_attack_paths(source_id, graph_name=self.prod_name)
        isolate_cypher = """
        MATCH (e:Entity)
        WHERE e.id IN $cut_nodes
        SET e.status = 'isolated'
        RETURN collect(e.id)
        """
        _, mut_tel = self._run(self.prod_name, isolate_cypher, {"cut_nodes": cut_nodes})
        post_paths, ver_tel = self.find_attack_paths(source_id, graph_name=self.prod_name)

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
