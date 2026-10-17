<p align="center">
  <img src="frontend/assets/tezcatl.jpg" alt="TEZCATL Graph Containment Engine" width="120" style="border-radius: 50%;" />
</p>

# TEZCATL — Graph-Native Breach Containment on FalkorDB

[![Live Deployment](https://img.shields.io/badge/Live%20Target-tezcatl--engine.onrender.com-blueviolet)](https://tezcatl-engine.onrender.com)
[![FalkorDB](https://img.shields.io/badge/FalkorDB-Multi--Graph-orange)](https://www.falkordb.com/)
[![Track 01](https://img.shields.io/badge/Track--01-Agents%20That%20Act%20on%20Connected%20Data-purple)](#)
[![Author](https://img.shields.io/badge/Author-Aadrit555-blue)](https://github.com/Aadrit555)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Pydantic](https://img.shields.io/badge/Validation-Pydantic%20v2-green)](https://pydantic.dev/)
[![FastAPI](https://img.shields.io/badge/Framework-FastAPI%20Production-teal)](https://fastapi.tiangolo.com/)
[![Zero External APIs](https://img.shields.io/badge/Keys-Zero%20External%20APIs-success)](#)

> **TEZCATL** is an incident containment engine submitted under **Track 01: Agents That Act on Connected Data** (WeMakeDevs & FalkorDB Graph Hacks). It isolates multi-hop cloud security breaches using FalkorDB graph traversals, native graph centrality algorithms (`algo.betweenness`), dynamic service impact analysis, and isolated shadow-graph sandbox verification (`tezcatl_mirror`).
>
> *Powered by native FalkorDB algorithms and 100% first-party deterministic graph orchestration. Zero external APIs. Zero third-party agent wrappers.*

---

## The "Take FalkorDB Out" Test: Why the Product Fails Without the Graph

> [!IMPORTANT]
> *"If the product still works once FalkorDB is taken out, the graph is decoration rather than the thing the product runs on — and is disqualified."*

If FalkorDB is removed from TEZCATL, the product cannot function:
1. **Multi-Hop Traversal Collapses:** Identifying lateral movement trajectories requires evaluating variable-length directed paths (`*1..8`). In relational SQL, this demands recursive common table expressions (CTEs) or deep nested self-joins that collapse as topological depth grows.
2. **Vector RAG Cannot Reason Over Reachability:** Embeddings compress semantic proximity, not topological connectivity or directional permissions. A vector database cannot compute whether severing an intermediate token cuts 100% of reachability to crown jewels.
3. **Native Betweenness Centrality Disappears:** TEZCATL executes `algo.betweenness` directly inside FalkorDB to locate structural choke points across entity nodes in under 3 milliseconds.
4. **Service Impact Blast Radius Is a Reverse Graph Traversal:** Computing business disruption is not a static lookup table—it executes dynamic multi-hop reverse dependency traversals (`(s:Service)-[:DEPENDS_ON*1..4]->(e:Entity)`) to sum real revenue impact scores.
5. **Multi-Scenario Graph Isolation:** Dynamic scenarios reside in strictly isolated server-controlled FalkorDB graphs (e.g. `prod_graph`, `scen_three_tier_prod`, `scen_microservices_prod`), preventing data corruption or test pollution.
6. **No Simulation Allowed:** The frontend contains zero mock arrays or simulated state. If FalkorDB is offline, the interface displays an explicit engine connection error banner.

---

## 3 Distinct Verified Scenarios

TEZCATL evaluates real security topologies stored directly in isolated FalkorDB graphs:

| Scenario | Graph Name | Description | Threat Model | Active Paths | Optimal Cut | Blast Cost |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Scenario A** | `prod_graph` / `tezcatl_mirror` | **CI/CD Pipeline Compromise (Canonical Demo)**: Ingress at `ci-runner-07`, dual token routes, `release-controller` choke point, `prod-signing-key` crown jewel. | **Active** | 2 paths | `{tok-deploy-alpha, tok-artifact-rw}` | **5** (vs 14) |
| **Scenario B** | `scen_three_tier_prod` | **Three-Tier Web Application (Architecture Only)**: Frontend, API Gateway, Order Worker, Redis Cache, Postgres Primary DB with `CALLS`, `READS_FROM`, `WRITES_TO`, `DEPENDS_ON`. | **None** (Architecture Mode) | 0 paths | `None` (Solver inactive) | **0** |
| **Scenario C** | `scen_microservices_prod` | **Microservices Branching & Cycle Topology**: Ingress at `edge-ingress`, feedback cycle between `order-processor` and `fraud-checker`, telemetry branch, `auth-broker` bottleneck, `vault-secrets`. | **Active** | 2 paths | `{telemetry-aggregator, fraud-checker}` | **8** (vs 9 or 14) |

---

## Normalized Security-Topology Manifest & Relationship Semantics

Alternative security topologies are validated using strict Pydantic v2 schemas:

```json
{
  "schema_version": 1,
  "project": {
    "id": "microservices-alternate",
    "name": "Scenario C: Microservices Branching & Cycle Topology"
  },
  "nodes": [
    {"id": "edge-ingress", "name": "Edge API Ingress", "kind": "gateway", "criticality": "critical", "status": "active"},
    {"id": "order-processor", "name": "Order Processor", "kind": "service", "criticality": "high", "status": "active"},
    {"id": "fraud-checker", "name": "Fraud Verification Service", "kind": "service", "criticality": "medium", "status": "active"},
    {"id": "telemetry-aggregator", "name": "Telemetry Aggregator", "kind": "service", "criticality": "low", "status": "active"},
    {"id": "auth-broker", "name": "Internal Auth Broker", "kind": "service", "criticality": "high", "status": "active"},
    {"id": "vault-secrets", "name": "HashiCorp Secrets Vault", "kind": "database", "criticality": "crown_jewel", "status": "active"}
  ],
  "edges": [
    {"id": "e1", "source": "edge-ingress", "target": "order-processor", "type": "ATTACK_STEP"},
    {"id": "e2", "source": "order-processor", "target": "fraud-checker", "type": "ATTACK_STEP"},
    {"id": "e3", "source": "fraud-checker", "target": "order-processor", "type": "CALLS"},
    {"id": "e4", "source": "fraud-checker", "target": "auth-broker", "type": "ATTACK_STEP"},
    {"id": "e5", "source": "edge-ingress", "target": "telemetry-aggregator", "type": "ATTACK_STEP"},
    {"id": "e6", "source": "telemetry-aggregator", "target": "auth-broker", "type": "ATTACK_STEP"},
    {"id": "e7", "source": "auth-broker", "target": "vault-secrets", "type": "ATTACK_STEP"}
  ],
  "scenario": {
    "source_id": "edge-ingress",
    "target_ids": ["vault-secrets"],
    "allowed_traversal_types": ["ATTACK_STEP"],
    "max_depth": 8,
    "eligible_mitigations": [
      {"node_id": "telemetry-aggregator", "blast_cost": 2, "impact_justification": "Temporary loss of application metrics"},
      {"node_id": "fraud-checker", "blast_cost": 6, "impact_justification": "Fraud checks queued for manual review"},
      {"node_id": "auth-broker", "blast_cost": 9, "impact_justification": "Central auth gateway outage"},
      {"node_id": "order-processor", "blast_cost": 14, "impact_justification": "Primary checkout pipeline blocked"}
    ]
  }
}
```

### Supported Relationship Types Allowlist
- `CALLS`: Service or RPC invocation (architecture relationship).
- `DEPENDS_ON`: Operational dependency for reverse blast radius calculation.
- `READS_FROM`: Data store read access.
- `WRITES_TO`: Data store write access.
- `ASSUMES_ROLE`: IAM STS role delegation.
- `DEPLOYS_TO`: Infrastructure continuous deployment link.
- `ATTACK_STEP`: Explicit verified lateral attack movement vector.

> [!NOTE]
> **Relationship Semantics:** Only explicit `ATTACK_STEP` relationships are traversed by the containment engine. Architecture edges (`CALLS`, `DEPENDS_ON`, `READS_FROM`, `WRITES_TO`) are rendered in neutral slate with distinct arrowheads and cannot be traversed as attacker movement. If a topology is loaded without an explicit threat model (Scenario B), TEZCATL renders the architecture in neutral mode and displays an explicit notice: *"Architecture topology loaded. Security analysis requires an explicit threat model."*

---

## Animated Flow & Dynamic SVG Graph Layout

- **Directional Animated Flows:** Active attack vectors are visualized with moving dashed crimson strokes (`animation: attackFlow 1.25s linear infinite` with `stroke-dasharray: 6 4` and `stroke-dashoffset: 20` to `0`).
- **Ray-to-Rectangle Boundary Clipping (`clipRayToRect`):** Computes exact intersection points of node boundary rectangles, ensuring arrowheads sit flush at any angle.
- **Cycle Handling:** Directed feedback cycles are detected during BFS leveling to prevent layer drift, and rendered as curved feedback loops without visual overlap.
- **Accessibility:** Full support for `@media (prefers-reduced-motion: reduce)` which pauses animations while preserving directional markers.
- **Responsive Viewports:** Verified across 320px, 375px, 768px, 1280px, and 1440px with zero horizontal body overflow (`scrollWidth <= innerWidth`).

---

## Core OpenCypher Queries (100% Parameterized)

All Cypher queries in TEZCATL use strict parameter binding with zero raw string interpolation or f-string injection.

### 1. Multi-Hop Attack Path Discovery (`*1..8`)
```cypher
MATCH (src:Entity {id: $source_id}), (target:Entity)
WHERE target.id IN $target_ids
MATCH p = (src)-[:ATTACK_STEP*1..8]->(target)
WHERE ALL(r IN relationships(p) WHERE coalesce(r.active, true) = true)
  AND NONE(n IN nodes(p) WHERE n.status = 'isolated')
RETURN target.id AS target_id,
       length(p) AS hops,
       [n IN nodes(p) | {id: n.id, name: n.name, kind: n.kind}] AS nodes,
       [r IN relationships(p) | {mechanism: r.mechanism, evidence_id: r.evidence_id}] AS edges
ORDER BY hops ASC
```

### 2. Native FalkorDB Betweenness Centrality
```cypher
CALL algo.betweenness({
    nodeLabels: ['Entity'],
    relationshipTypes: ['ATTACK_STEP']
})
YIELD node, score
RETURN node.id, score
ORDER BY score DESC
```

### 3. Dynamic Service Blast Radius via Reverse Dependency Traversal
```cypher
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
```

### 4. Shadow Graph Sandbox Containment & Verification
```cypher
// Sever candidate entities in isolated scenario mirror graph
MATCH (e:Entity)
WHERE e.id IN $cut_nodes
SET e.status = 'isolated'
RETURN count(e);

// Verify reachability in mirror drops to 0
MATCH (src:Entity {id: $source_id}), (target:Entity {criticality: 'crown_jewel'})
MATCH p = (src)-[:ATTACK_STEP*1..8]->(target)
WHERE ALL(r IN relationships(p) WHERE coalesce(r.active, true) = true)
  AND NONE(n IN nodes(p) WHERE n.status = 'isolated')
RETURN count(p) AS remaining_paths;
```

---

## Quickstart & Verification

TEZCATL requires **no external API keys, no cloud credentials, and no .env configuration**.

### 1. Launch via Docker Compose
```bash
docker-compose up -d
```

### 2. Run the Full Integration & Scenario Test Suite
```bash
# Run all 11 backend, scenario, and visual browser tests
pytest -v
```

### 3. Run Live Feature Benchmark
```bash
python verify_live_features.py
```

### 4. Run Browser Visual Regression Tests
```bash
python tests/test_browser_visual.py
```

---

## Test Suite Results (11/11 Passed)

```text
============================= test session starts =============================
tests/test_browser_visual.py::test_responsive_hero_and_animated_flow PASSED [  9%]
tests/test_isolated_scenarios.py::test_scenario_a_baseline_topology PASSED [ 18%]
tests/test_isolated_scenarios.py::test_scenario_b_bypass_architecture PASSED [ 27%]
tests/test_isolated_scenarios.py::test_scenario_c_contained_topology PASSED [ 36%]
tests/test_isolated_scenarios.py::test_scenario_d_new_nodes_and_branches PASSED [ 45%]
tests/test_tezcatl.py::test_end_to_end_falkordb_suite PASSED             [ 54%]
tests/test_three_scenarios.py::test_scenario_a_canonical_cicd PASSED     [ 63%]
tests/test_three_scenarios.py::test_scenario_b_three_tier_app_no_threat_model PASSED [ 72%]
tests/test_three_scenarios.py::test_scenario_c_microservices_cycles_and_branches PASSED [ 81%]
tests/test_three_scenarios.py::test_manifest_validation_rules PASSED     [ 90%]
tests/test_three_scenarios.py::test_scenario_isolation PASSED            [100%]
============================= 11 passed in 38.13s =============================
```

---

## Repository Structure

```text
we-make-devs-GRAPH_HACKS/
├── backend/
│   ├── __init__.py           # Package marker
│   ├── config.py             # FalkorDB host/port environment bindings and manifest limits
│   ├── models.py             # Strict Pydantic v2 schemas and allowlist validation
│   ├── scenarios.py          # Pre-registered Scenarios A, B, C & ScenarioRegistry
│   ├── seed.py               # Idempotent database bootstrap for canonical entities & services
│   ├── graph_client.py       # Parameterized OpenCypher client, multi-scenario cloner, telemetry
│   ├── solver.py             # Deterministic minimum-cost vertex-cut combinatorial engine
│   └── main.py               # Production FastAPI application & scenario REST endpoints
├── frontend/
│   ├── index.html            # Minimal Meadow landing view with on-demand interactive console
│   └── assets/
│       └── tezcatl.jpg       # Aztec obsidian crest brand mark
├── screenshots/              # Real Playwright Edge browser screenshots (viewports & scenarios)
│   ├── console_baseline.png
│   ├── console_bypass_active.png
│   ├── console_contained.png
│   ├── console_scenario_a.png
│   ├── console_scenario_b_architecture.png
│   ├── console_scenario_c_cycles.png
│   ├── landing_desktop_1440.png
│   ├── landing_laptop_1280.png
│   ├── landing_tablet_768.png
│   ├── landing_mobile_375.png
│   └── landing_mobile_320.png
├── tests/
│   ├── test_browser_visual.py      # Playwright browser visual regression & animation suite
│   ├── test_isolated_scenarios.py  # Multi-scenario isolated graph tests
│   ├── test_tezcatl.py             # Live FalkorDB 6-feature test suite
│   └── test_three_scenarios.py     # Scenarios A, B, C, validation, and isolation tests
├── Dockerfile                # Production container deployment for Render
├── docker-compose.yml        # Local orchestrated spin-up
├── requirements.txt          # Pure first-party dependencies
├── verify_live_features.py   # Live FalkorDB benchmark & feature audit script
├── pytest.ini                # Pytest configuration
├── README.md                 # Complete hackathon submission documentation
└── SUBMISSION_GUIDE.md       # WeMakeDevs & FalkorDB portal answers & demo script
```

---

## Mandatory Engineering & AI Tooling Disclosure

In accordance with official hackathon submission guidelines:
- **Architect & Author:** Aadrit555 (`https://github.com/Aadrit555`)
- **First-Party Codebase:** 100% first-party systems engineering, graph algorithms, and determinism.
- **AI Tooling Usage:** Google Antigravity coding assistant was utilized as a pair programmer for refactoring boilerplate, drafting Pytest suites, running Docker commands, and formatting documentation.
- **Execution Sovereignty:** Zero proprietary LLMs, zero third-party agent frameworks, and zero external APIs are invoked at runtime. Every graph traversal and calculation executes strictly inside the local FalkorDB and Python stack.
