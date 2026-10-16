<p align="center">
  <img src="assets/tezcatl_banner.png" alt="TEZCATL Graph Containment Engine" width="450" />
</p>

# TEZCATL — Graph-Native Breach Containment on FalkorDB

[![FalkorDB](https://img.shields.io/badge/FalkorDB-Multi--Graph-orange)](https://www.falkordb.com/)
[![Track 01](https://img.shields.io/badge/Track--01-Agents%20That%20Act%20on%20Connected%20Data-purple)](#)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Pydantic](https://img.shields.io/badge/Validation-Pydantic%20v2-green)](https://pydantic.dev/)
[![FastAPI](https://img.shields.io/badge/Framework-FastAPI%20Production-teal)](https://fastapi.tiangolo.com/)
[![Protocol](https://img.shields.io/badge/MCP-JSON--RPC%202.0-blue)](#)
[![Tests](https://img.shields.io/badge/Tests-50%2F50%20Passing-brightgreen)](tests/)
[![Zero External APIs](https://img.shields.io/badge/Keys-Zero%20External%20APIs-success)](#)

> **TEZCATL** is an incident containment engine that isolates multi-hop cloud security breaches using FalkorDB graph traversals, native graph centrality algorithms (`algo.betweenness`), dynamic service impact analysis, and isolated shadow-graph sandbox verification (`tezcatl_mirror`).
>
> *Powered by native FalkorDB algorithms and 100% first-party deterministic graph orchestration. Zero external APIs. Zero third-party agent wrappers.*

---

## The Core Problem: Why Relational Databases and Vector RAG Fail at Breach Containment

When a CI/CD build runner or developer workstation is compromised, attackers move laterally across identities, temporary credentials, workloads, and artifact registries to reach high-value crown-jewel assets like production signing keys.

1. **Relational / SQL Tables:** Querying variable-length multi-hop lateral movement (`*1..8`) requires recursive common table expressions (CTEs) or repeated expensive self-joins that collapse under real-world infrastructure complexity.
2. **Vector RAG:** Vector embeddings compress semantic similarity, not directional reachability. A vector store cannot guarantee that severing a specific credential severs 100% of reachable paths.
3. **Naive Sledgehammer Fixes:** Without topological visibility, incident responders often shut down large shared bottlenecks (such as the main Release Controller), taking downstream revenue services offline unnecessarily.

**TEZCATL solves this deterministically in FalkorDB:** It traverses every active directed path, calculates structural bottlenecks using native graph algorithms, evaluates operational service dependencies, and isolates the minimum-cost cut-set inside a cloned shadow graph before touching production.

---

## Why FalkorDB (The Core Architecture)

FalkorDB serves as the central calculation engine across four synchronized graph operations:

1. **Variable-Length Path Traversal (`*1..8`):**
   ```cypher
   MATCH p = (src:Entity {id: $source_id})-[:ATTACK_STEP*1..8]->(target:Entity {criticality: 'crown_jewel'})
   WHERE ALL(r IN relationships(p) WHERE r.active = true)
     AND ALL(n IN nodes(p) WHERE n.status <> 'disabled')
   RETURN [n IN nodes(p) | n.id] AS node_ids, [r IN relationships(p) | r.mechanism] AS mechanisms, length(p) AS hops
   ```
   Evaluates all ingress trajectories from the breached runner to protected assets in sub-millisecond latency.

2. **Native Centrality Algorithms (`algo.betweenness`):**
   Executes native betweenness centrality over all infrastructure entities in the graph to identify structural bridges and choke points.

3. **Dynamic Downstream Service Impact Weighting:**
   ```cypher
   MATCH (s:Service)-[:DEPENDS_ON*1..4]->(e:Entity)
   WHERE e.id IN $candidate_ids
   RETURN e.id AS entity_id,
          count(DISTINCT s) AS downstream_service_count,
          sum(s.revenue_impact_score) AS blast_radius_cost,
          collect(DISTINCT s.name) AS impacted_services
   ```
   Reverses operational dependency trees to dynamically calculate the true disruption cost of severing each candidate node.

4. **Multi-Graph Shadow Sandbox (`tezcatl_mirror`):**
   Uses `db.select_graph("tezcatl_mirror")` to clone `prod_graph`, apply candidate mutations in memory, and verify that remaining paths drop to zero before human authorization commits the change.

---

## Why No LLM Training or External API Keys Are Needed

Security containment demands exact mathematical proofs, zero hallucinations, and absolute reliability under pressure:
- **Exact Hitting-Set Math:** TEZCATL models breach containment as a minimum-weight vertex-cut / hitting-set problem over candidate graph nodes. The solver guarantees 100% path severance with lowest operational disruption.
- **Zero Hallucination:** Every recommendation is backed by a verifiable Cypher query record, execution latency timestamp, and SHA-256 graph state hash.
- **Self-Contained:** Runs without OpenAI, Anthropic, Gemini, or third-party agent orchestration frameworks (`langchain`, `llamaindex`, `crewai`).

---

## Quickstart (Zero Configuration)

TEZCATL requires **no external API keys, no cloud credentials, and no .env configuration**.

### Option A: Docker Compose (Recommended)

```bash
# Clone repository & launch stack
git clone https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS.git
cd we-make-devs-GRAPH_HACKS
docker compose up --build
```

Access points:
- **Interactive Graph Console:** `http://localhost:8000`
- **FalkorDB Instance:** `localhost:6379`

### Option B: Local Python Virtual Environment

```bash
# 1. Start FalkorDB
docker run -d --name tezcatl-falkordb --restart unless-stopped -p 127.0.0.1:6379:6379 falkordb/falkordb:latest

# 2. Setup Virtual Environment & Install Dependencies
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 3. Seed Topology & Run Pytest Suite
python seed.py
pytest -v

# 4. Launch Application
uvicorn backend.main:app --reload --port 8000
```

---

## Containment Decision Matrix

| Option | Selected Action(s) | Impact Cost | Downstream Services Affected | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Option A (Optimal)** | Revoke `deploy_token` + `artifact_token` | **5** ($2 + 3$) | Staging Deployer (2) + Artifact Publisher (3) | **SELECTED** |
| **Option B (Suboptimal)** | Disable `signer_role` | **8** | Canary Rollout (4) + Binary Attestation (4) | Rejected (higher cost) |
| **Option C (Brute Force)** | Shutdown `release_controller` | **10** | Checkout API (5) + Billing Worker (3) + Release Pipeline (2) | Rejected (2x higher cost) |
| **Option D (Incomplete)** | Revoke `deploy_token` alone | 2 | Leaves artifact route active | Rejected (1 path remains) |
| **Option E (Incomplete)** | Revoke `artifact_token` alone | 3 | Leaves deploy routes active | Rejected (2 paths remain) |

---

## Repository Structure

```text
we-make-devs-GRAPH_HACKS/
├── config.py                 # Typed configuration and FalkorDB connection settings
├── models.py                 # Strict Pydantic domain models & JSON-RPC 2.0 MCP schemas
├── seed.py                   # Deterministic breach topology & dependency tree seed script
├── graph_client.py           # Parameterized OpenCypher client, telemetry profiler, shadow cloner
├── solver.py                 # Deterministic minimum-cost vertex-cut combinatorial engine
├── agent.py                  # Track 01 autonomous agent orchestrator
├── mcp_server.py             # First-party JSON-RPC 2.0 Model Context Protocol tool server
├── app.py                    # Production FastAPI application & REST/MCP endpoints
├── backend/
│   └── main.py               # Uvicorn entry point
├── frontend/
│   └── index.html            # Minimal Meadow landing view with on-demand interactive console
├── assets/
│   └── tezcatl_banner.png    # Project banner graphic
├── Dockerfile                # Production container definition
├── docker-compose.yml        # Multi-container orchestration stack
├── requirements.txt          # Pure first-party dependencies
├── pytest.ini                # Pytest configuration
└── tests/
    ├── test_tezcatl.py       # Core unit, agent, MCP, and API test suite
    ├── test_graph_engine_integration.py # Live FalkorDB client integration tests
    └── test_seed_integration.py         # Seed topology integrity tests
```

---

## Test Verification

Run all test cases against the live FalkorDB instance:
```bash
pytest -v
```

All 50 test cases pass across:
- Parameterized Cypher execution and zero query string interpolation
- Cold-start auto-bootstrapping on empty graphs
- Multi-hop traversal bounds (`*1..8`) and evidence ID integrity
- Native FalkorDB betweenness centrality (`algo.betweenness`)
- Reverse dependency service impact analysis
- Exact combinatorial minimum-cost cut selection (cost 5 vs. cost 10)
- Operator protection exclusions (`exclude_ids`)
- First-party JSON-RPC 2.0 MCP tool execution (`tools/list` and `tools/call`)
- Shadow-graph sandbox isolation (`tezcatl_mirror` vs. `prod_graph`)
- End-to-end incident analysis and gated containment commit
- SHA-256 pre/post state integrity audit receipts
- Complete FastAPI HTTP REST and MCP endpoints
