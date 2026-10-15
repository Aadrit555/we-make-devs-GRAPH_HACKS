# TEZCATL // Track 01: Agents That Act on Connected Data
### Graph-Native Obsidian Containment Engine Powered by FalkorDB

[![FalkorDB](https://img.shields.io/badge/FalkorDB-Multi--Graph-orange)](https://www.falkordb.com/)
[![Track 01](https://img.shields.io/badge/Track--01-Agents%20That%20Act%20on%20Connected%20Data-purple)](#)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Pydantic](https://img.shields.io/badge/Validation-Pydantic%20v2-green)](https://pydantic.dev/)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-red)](https://streamlit.io/)
[![Protocol](https://img.shields.io/badge/MCP-JSON--RPC%202.0-blue)](#)
[![Tests](https://img.shields.io/badge/Tests-100%25%20Passing-brightgreen)](tests/)
[![Zero External APIs](https://img.shields.io/badge/Keys-Zero%20External%20APIs-success)](#)

> **TEZCATL** is a sovereign, zero-API-key autonomous agent that solves multi-hop cloud security breaches by leveraging FalkorDB graph traversals, native centrality algorithms, dynamic service blast-radius calculations, and isolated shadow-mirror sandbox verification.

---

## ⚡ The Problem: Why Vector RAG & SQL Fail at Security Reachability
When a CI/CD build runner is compromised, attackers move laterally through complex, multi-hop permissions across identities, credentials, workloads, and secrets to reach a production signing key.
- **Standard Vector/SQL Stack:** Cannot reliably follow variable-length multi-hop relationships (`*1..8`), leading traditional tools to use a "sledgehammer" (shutting down the entire shared `Release Controller` and causing massive operational paralysis).
- **TEZCATL:** Uses FalkorDB to trace every active attack path, calculate structural choke points, and execute a combinatorial minimum-cost cut-set solver to find the exact surgical fix (revoking two minor tokens) while keeping critical production services online.

---

## 🏗️ Architecture & Track 01 Compliance
TEZCATL fulfills every requirement of **Track 01: Agents That Act on Connected Data** using 100% first-party Python code and FalkorDB native features:
1. **Multi-Hop OpenCypher Traversal:** Discovers active attack paths (`*1..8`) across dynamic node topologies using parameterized queries.
2. **Native Graph Algorithm Tools:** Executes FalkorDB's `algo.betweenness` procedure to quantify structural bottlenecks.
3. **Dynamic Service Blast Radius:** Reverse-traverses downstream `:Service` dependency trees (`[:DEPENDS_ON*1..4]`) to calculate live operational disruption costs.
4. **First-Party JSON-RPC 2.0 MCP Protocol:** Exposes all graph tools via a standardized Model Context Protocol server (`mcp_server.py`).
5. **Smoking-Mirror Multi-Graph Sandbox:** Clones `prod_graph` into an isolated `tezcatl_mirror` sandbox to mathematically verify `remaining_paths == 0` before committing cuts to production.
6. **Cryptographic State Audit Receipts:** Verifies SHA-256 graph state integrity pre- and post-mitigation, ensuring zero hallucination.

---

## 🚀 1-Command Local Deployment (Zero API Keys Required)

TEZCATL requires **no external API keys, no cloud credentials, and no .env configuration**.

### Option A: Docker Compose (Recommended)
```bash
# Clone repository & launch stack
git clone https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS.git
cd we-make-devs-GRAPH_HACKS
docker compose up --build
```
Access points:
- **TEZCATL Incident Command Console:** `http://localhost:8501`
- **FalkorDB Client:** `localhost:6379`

### Option B: Local Virtual Environment
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

# 4. Launch Console
streamlit run app.py
```

---

## 🔬 FalkorDB Graph Schema & Relationship Semantics

### Node Labels
- `:Entity`: Infrastructure workload, credential, role, session, registry, or key (`id`, `name`, `kind`, `criticality`, `cost`, `status`).
- `:Service`: Dependent production service (`id`, `name`, `revenue_impact_score` between 1 and 5).

### Directed Relationships
- `[:ATTACK_STEP]`: Models lateral movement traversals (`active`, `mechanism`, `evidence_id`).
- `[:DEPENDS_ON]`: Models operational dependencies from services to entities (`purpose`).

### Dynamic Blast-Radius Reverse Query
```cypher
MATCH (s:Service)-[:DEPENDS_ON*1..4]->(e:Entity)
WHERE e.id IN $candidate_ids
RETURN e.id AS entity_id,
       count(DISTINCT s) AS downstream_service_count,
       sum(s.revenue_impact_score) AS blast_radius_cost,
       collect(DISTINCT s.name) AS impacted_services
ORDER BY blast_radius_cost ASC, entity_id ASC
```

---

## ⚖️ The Containment Trade-Off Decision Matrix

| Option | Selected Action(s) | Graph-Computed Blast Radius | Downstream Disruption | Decision |
| :--- | :--- | :--- | :--- | :--- |
| **Option A (Optimal)** | Revoke `deploy_token` + `artifact_token` | **5** ($2 + 3$) | Staging Deployer (2) + Artifact Publisher (3) | **SELECTED** |
| **Option B (Suboptimal)** | Disable `signer_role` | **8** | Canary Rollout (4) + Binary Attestation (4) | Rejected (higher cost) |
| **Option C (Brute Force)** | Shutdown `release_controller` | **10** | Checkout API (5) + Billing Worker (3) + Release Pipeline (2) | Rejected (2x higher cost) |
| **Option D (Incomplete)** | Revoke `deploy_token` alone | 2 | Leaves artifact route active | Rejected (1 path remains) |
| **Option E (Incomplete)** | Revoke `artifact_token` alone | 3 | Leaves deploy routes active | Rejected (2 paths remain) |

---

## 📂 Repository File Layout

```text
we-make-devs-GRAPH_HACKS/
├── config.py             # FalkorDB connection settings (Zero API keys)
├── models.py             # Strict Pydantic domain models & JSON-RPC 2.0 MCP schemas
├── seed.py               # Deterministic breach topology & dependency tree
├── graph_client.py       # Parameterized Cypher runner, multi-graph cloner, auto-bootstrap
├── solver.py             # Combinatorial minimum-cost vertex-cut engine
├── agent.py              # Sovereign Track 01 autonomous agent orchestrator
├── mcp_server.py         # First-party JSON-RPC 2.0 Model Context Protocol tool server
├── app.py                # Streamlit SecOps Console with live query & sandbox telemetry
├── Dockerfile            # Container definition
├── docker-compose.yml    # One-command FalkorDB + Tezcatl deployment
├── requirements.txt      # Minimal, pure first-party dependencies
├── .streamlit/           # Dark monospace UI theme
└── tests/test_tezcatl.py # Comprehensive pytest test suite
```

---

## 🧪 Comprehensive Test Suite

Run all verification tests:
```bash
pytest -v
```

All 26 comprehensive test cases pass across:
- Zero query interpolation / pure parameterization
- Cold-start auto-bootstrapping on empty graphs
- Multi-hop traversal bounds (`*1..8`) and evidence ID integrity
- Native FalkorDB betweenness centrality (`algo.betweenness`)
- Reverse dependency blast-radius calculation
- Exact combinatorial minimum-cost cut selection (cost 5 vs. cost 10)
- Operator protection exclusions (`exclude_ids`)
- First-party JSON-RPC 2.0 MCP tool execution (`tools/list` and `tools/call`)
- Smoking Mirror sandbox isolation (`tezcatl_mirror` vs. `prod_graph`)
- Autonomous agent end-to-end incident investigation
- Human-in-the-loop authorization gate, post-action zero-path verification, and cryptographic receipts
