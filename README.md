# TEZCATL — Obsidian Mirror Graph Containment Engine

[![FalkorDB](https://img.shields.io/badge/FalkorDB-Multi--Graph-orange)](https://www.falkordb.com/)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Pydantic](https://img.shields.io/badge/Validation-Pydantic%20v2-green)](https://pydantic.dev/)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-red)](https://streamlit.io/)
[![Tests](https://img.shields.io/badge/Tests-51%20Passed-brightgreen)](tests/)
[![Architecture](https://img.shields.io/badge/Architecture-100%25%20First--Party%20Python-purple)](#)
[![Zero External APIs](https://img.shields.io/badge/APIs-Zero%20External%20APIs-success)](#)

> *"Multi-Hop Breach Discovery, Blast-Radius Calculus & Shadow-Graph Verification powered by FalkorDB"*

**TEZCATL** (named after the Aztec Lord of the Smoking Obsidian Mirror) is a pure-graph incident containment engine built for the **WeMakeDevs / FalkorDB Graph Hacks Hackathon (Track 01: Agents That Act on Connected Data)**.

TEZCATL scries a compromised CI/CD workload runner, traces all modeled directed attack paths to a production signing key (crown jewel) within an 8-hop bound, computes downstream operational blast radius dynamically via reverse multi-hop graph dependency traversal, verifies counterfactual containment in an isolated **Smoking Mirror sandbox** (`tezcatl_mirror`) without touching production, requires an explicit human authorization gate, applies the minimum-disruption cut to `prod_graph`, verifies 0 remaining paths, and generates a downloadable **Cryptographic Containment Audit Receipt** with pre/post SHA-256 state integrity hashes.

---

## 1. What TEZCATL Does and Does Not Do

### What TEZCATL Does
- **100% First-Party 5-Stage Sovereign Pipeline (`pipeline.py`):**
  - **Stage 1 (Intent & Entity Resolution):** Pure first-party tokenizer and live FalkorDB catalog matcher. Resolves source, target, operator-pinned exclusions (`exclude_ids`), and hop bounds with zero external APIs.
  - **Stage 2 (Graph Scrying & Telemetry Dispatcher):** Dispatches parameterized OpenCypher tools decorated with `@tezcatl_tool` (`scry_attack_paths`, `rank_betweenness_bottlenecks`, `compute_service_blast_radius`).
  - **Stage 3 (Combinatorial Minimum-Cut Solver):** Pure hitting-set algorithm with graph-computed blast radius costs and operator protection constraints.
  - **Stage 4 (Smoking Mirror Sandbox Simulator):** Clones topology to `tezcatl_mirror`, applies simulated cut, and asserts zero remaining paths.
  - **Stage 5 (Tactical Compiler & Cryptographic Auditor):** Computes pre/post SHA-256 graph hashes, identifies spared high-centrality bridges, and produces an immutable `ContainmentAuditReceipt`.
- **Obsidian Scrying Engine:** Traverses directed `ATTACK_STEP` relationships from `$source_id` to `crown_jewel` targets using strictly parameterized OpenCypher on live FalkorDB.
- **Structural Bottleneck Discovery:** Executes FalkorDB's native `algo.betweenness` procedure over directed relationships to pinpoint high-traffic bridge entities.
- **Dynamic Blast-Radius Calculus:** Dynamically computes operational disruption via reverse multi-hop dependency traversal (`MATCH (s:Service)-[:DEPENDS_ON*1..4]->(e:Entity)`), summing unique downstream `:Service` revenue impact scores (1–5) rather than relying on static node properties.
- **Deterministic Combinatorial Optimizer:** Computes the lowest-cost vertex cut that intersects 100% of discovered attack paths, proving mathematically that revoking both credentials (blast radius 5) beats shutting down the production controller (blast radius 10).
- **Smoking Mirror Multi-Graph Sandbox:** Uses FalkorDB's native multi-graph capabilities to clone the topology into an isolated sandbox (`tezcatl_mirror`). Evaluates candidate severing and verifies 0 remaining paths in the shadow graph before mutating production.
- **Cryptographic Containment Receipt:** Generates an inspectable and downloadable JSON/Markdown audit receipt containing pre-mitigation and post-mitigation SHA-256 graph state hashes, spared high-centrality bottlenecks (`release_controller` spared, keeping `Checkout API`, `Billing Worker`, `Release Pipeline` online), and exact Cypher execution latencies.
- **Cold-Start Auto-Bootstrapping:** Graph client automatically detects empty graphs on startup (`node_count == 0`) and triggers idempotent seeding.

### What TEZCATL Does Not Do
- **Zero External APIs:** Pure first-party sovereign Python execution; zero external SaaS or LLM APIs required.
- **Zero Third-Party Agent Frameworks:** Zero third-party agent framework abstractions. All logic is 100% custom-written first-party Python owned by Aadrit555.
- **No Mock Databases or Silent Fallbacks:** All paths, costs, centrality scores, and verification counts originate from live queries against FalkorDB.
- **No Hallucinated Actions:** Actions are strictly verified via counterfactual sandbox simulation before human execution approval.

---

## 2. Graph Schema & Relationship Semantics

### Node Labels: `:Entity` and `:Service`
- `id` (String): Unique identifier (e.g. `ci_runner`, `deploy_token`, `signing_key`, `checkout_api`).
- `name` (String): Display name.
- `kind` (String): `workload`, `credential`, `iam_role`, `registry`, `service`, `key`, `session`, `artifact`, `cluster`, `host`, `trust_binding`.
- `criticality` (String): `low`, `medium`, `high`, `critical`, `crown_jewel`.
- `cost` (Integer): Operational impact disruption score ($\ge 0$).
- `revenue_impact_score` (Integer, 1–5): Applied to `:Service` nodes for dynamic blast-radius calculation.
- `status` (String): `active`, `compromised`, `disabled`.

### Directed Relationship: `ATTACK_STEP`
Used exclusively for attack reachability:
- `mechanism` (String): Modeled technical mechanism.
- `active` (Boolean): Current status of the attack path.
- `evidence_id` (String): Reference ID (e.g. `E-001` through `E-010`).

### Directed Relationship: `DEPENDS_ON`
Used for operational service dependencies (`runs_on`, `deploys_to`, `consumes_from`).
Used in reverse traversal:
```cypher
MATCH (s:Service)-[:DEPENDS_ON*1..4]->(e:Entity)
WHERE e.id IN $candidate_ids
RETURN e.id AS entity_id, count(DISTINCT s) AS downstream_service_count,
       sum(s.revenue_impact_score) AS blast_radius_cost,
       collect(DISTINCT s.name) AS impacted_services
```

---

## 3. Seed Topology & Blast Radius Trade-Off

### Attack Trajectory Topology (3 Distinct Paths)
```text
ci_runner ──[E-004]──> artifact_token ──[E-005]──> artifact_registry ──[E-006]──┐
ci_runner ──[E-001]──> deploy_token   ──[E-007]──> legacy_session    ──[E-008]──┼──> release_controller ──[E-009]──> signer_role ──[E-010]──> signing_key
ci_runner ──[E-001]──> deploy_token   ──[E-002]──> deploy_role       ──[E-003]──┘
```

### The Containment Trade-Off
| Option | Selected Action(s) | Graph-Computed Blast Radius | Downstream Disruption | Decision |
| :--- | :--- | :--- | :--- | :--- |
| **Option A (Optimal)** | Revoke `deploy_token` + `artifact_token` | **5** ($2 + 3$) | Staging Deployer (2) + Artifact Publisher (3) | **SELECTED** |
| **Option B (Suboptimal)** | Disable `signer_role` | **8** | Canary Rollout (4) + Binary Attestation (4) | Rejected (higher cost) |
| **Option C (Brute Force)** | Shutdown `release_controller` | **10** | Checkout API (5) + Billing Worker (3) + Release Pipeline (2) | Rejected (2x higher cost) |
| **Option D (Incomplete)** | Revoke `deploy_token` alone | 2 | Leaves artifact route active | Rejected (1 path remains) |
| **Option E (Incomplete)** | Revoke `artifact_token` alone | 3 | Leaves deploy routes active | Rejected (2 paths remain) |

---

## 4. Quickstart & Deployment

### One-Command Docker Deployment (Recommended)
```powershell
docker compose up --build -d
```
This automatically boots FalkorDB and TEZCATL, with cold-start auto-bootstrapping enabled.
- FalkorDB: `localhost:6379`
- TEZCATL Incident Command Console: `http://localhost:8501`

### Local Virtual Environment Run
```powershell
# 1. Start FalkorDB
docker run -d --name tezcatl-falkordb --restart unless-stopped `
  -p 127.0.0.1:6379:6379 -p 127.0.0.1:3000:3000 `
  falkordb/falkordb:latest

# 2. Setup Virtual Environment
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 3. Seed Topology & Run Tests
python seed.py
pytest -v

# 4. Launch Console
streamlit run app.py
```

---

## 5. Automated Test Suite Breakdown (51 Passed)

| Test File | Focus Area | Passing Tests |
| :--- | :--- | :--- |
| `tests/test_tezcatl.py` | 5-stage sovereign pipeline, natural language parsing, tool dispatch, sandbox simulation, audit receipt, E2E | 9 |
| `tests/test_audit_hardening_integration.py` | Security regex, read-only segregation, telemetry, blast radius, mirror sandbox, audit receipt | 9 |
| `tests/test_graph_engine_integration.py` | Query 1 discovery, Query 2 centrality, Query 3 counterfactuals, candidate retrieval | 8 |
| `tests/test_cut_set_calculator.py` | Combinatorial optimizer, cost-5 assertion, candidate cap, protected endpoints, edge cases | 15 |
| `tests/test_action_verification_integration.py` | Freshness revalidation, state mutation, post-action zero-path verification | 3 |
| `tests/test_seed_integration.py` | Schema, node/edge counts, types, idempotency, path verification | 7 |
| **Total** | **Comprehensive Full System Coverage** | **51 / 51 PASSED** |

---

## 6. Repository Layout

```text
we-make-devs-GRAPH_HACKS/
├── config.py             # Strict pydantic-settings configuration (zero API keys)
├── models.py             # Strict Pydantic domain models, telemetry, and audit receipts
├── graph_client.py       # Hardened FalkorDB client, parameterized Cypher, auto-bootstrapping
├── solver.py             # Pure combinatorial hitting-set minimum-cost vertex cut solver
├── pipeline.py           # 5-Stage Tezcatl Sovereign Execution Pipeline
├── app.py                # Streamlit SecOps Console with live pipeline inspector & stress tools
├── seed.py               # Deterministic pristine topology generator
├── Dockerfile            # Production container packaging
├── docker-compose.yml    # One-command FalkorDB + Tezcatl deployment
├── requirements.txt      # Minimal, pure first-party dependencies
├── .streamlit/           # Dark monospace UI theme
└── tests/                # 51 passing unit and integration tests
```
