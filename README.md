# CUTLINE v2 — Graph-Native Attack Path Containment Planner

[![FalkorDB](https://img.shields.io/badge/FalkorDB-latest-orange)](https://www.falkordb.com/)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Pydantic](https://img.shields.io/badge/Validation-Pydantic%20v2-green)](https://pydantic.dev/)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-red)](https://streamlit.io/)
[![Tests](https://img.shields.io/badge/Tests-33%20Passed-brightgreen)](tests/)

**CUTLINE v2** is a graph-native attack-path containment planner built for the **WeMakeDevs / FalkorDB Graph Hacks Hackathon (Track 01: Agents That Act on Connected Data)**.

CUTLINE investigates a compromised CI/CD workload runner, discovers all modeled directed attack paths to a production signing key (crown jewel) within an 8-hop bound, deterministically calculates the lowest-cost vertex-cut containment plan using actual entity costs from FalkorDB, requires an explicit human authorization click, simulates containment in the graph, and executes a fresh post-action verification query to prove zero active attack paths remain.

---

## 1. What CUTLINE Does and Does Not Do

### What CUTLINE Does
- **Multi-Hop Graph Discovery:** Traverses directed `ATTACK_STEP` relationships from `$source_id` to `crown_jewel` targets using parameterized OpenCypher on live FalkorDB.
- **Structural Bottleneck Discovery:** Executes FalkorDB's native `algo.betweenness` procedure to compute exact graph centrality.
- **Deterministic Combinatorial Optimizer:** Computes the lowest-cost vertex cut that intersects every discovered attack path, proving mathematically that revoking both credentials (cost 5) beats shutting down the production controller (cost 10).
- **Endpoint Protection:** Automatically protects the starting source node and crown-jewel assets from being disabled.
- **State Freshness & Human Approval:** Enforces an explicit human approval gate. Revalidates graph freshness before mutation to reject stale or ineffective plans.
- **Closed-Loop Verification:** Updates actual graph state in FalkorDB (`status='disabled'`, `active=false`) and runs a fresh counterfactual Cypher query to verify 0 paths remain.
- **Grounded LLM Layer:** Optional OpenAI SDK intent router and evidence summarizer that strictly explains backend findings with zero hallucination.

### What CUTLINE Does Not Do
- **No Production Remediation:** All attack relationships, infrastructure assets, and impact costs are synthetic local demonstration artifacts. It does not touch real AWS, GitHub, or Kubernetes systems.
- **No LLM Calculation:** The LLM never writes Cypher, mutates graph state, or determines the optimal cut.
- **No Mock Databases:** All paths, costs, centrality scores, and verification counts originate from live queries against FalkorDB.

---

## 2. Graph Schema & Relationship Semantics

### Node Label: `Entity`
- `id` (String): Unique identifier (e.g. `ci_runner`, `deploy_token`, `signing_key`).
- `name` (String): Display name.
- `kind` (String): `workload`, `credential`, `iam_role`, `registry`, `service`, `key`, `session`, `artifact`, `cluster`, `host`, `trust_binding`.
- `criticality` (String): `low`, `medium`, `high`, `critical`, `crown_jewel`.
- `cost` (Integer): Synthetic operational impact disruption score ($\ge 0$).
- `status` (String): `active`, `compromised`, `disabled`.

### Directed Relationship: `ATTACK_STEP`
Used exclusively for attack reachability:
- `mechanism` (String): Explains the modeled technical mechanism.
- `active` (Boolean): Current status of the attack path.
- `evidence_id` (String): Reference ID (e.g. `E-001` through `E-010`).

### Directed Relationship: `DEPENDS_ON`
Used for operational dependencies (e.g. `runs_on`, `deploys_to`). Traversal queries ignore `DEPENDS_ON` to prevent false reachability assumptions.

---

## 3. Seed Topology & The Cost-5 vs Cost-10 Decision

### Initial Attack Topology (3 Distinct Paths)
```text
ci_runner ──[E-004]──> artifact_token ──[E-005]──> artifact_registry ──[E-006]──┐
ci_runner ──[E-001]──> deploy_token   ──[E-007]──> legacy_session    ──[E-008]──┼──> release_controller ──[E-009]──> signer_role ──[E-010]──> signing_key
ci_runner ──[E-001]──> deploy_token   ──[E-002]──> deploy_role       ──[E-003]──┘
```

### The Containment Trade-Off
| Option | Selected Action(s) | Modeled Disruption Cost | Paths Severed | Decision |
| :--- | :--- | :--- | :--- | :--- |
| **Option A (Optimal)** | Revoke `deploy_token` + `artifact_token` | **5** ($2 + 3$) | **3 of 3 (100%)** | **SELECTED** |
| **Option B (Suboptimal)** | Disable `signer_role` | **8** | 3 of 3 (100%) | Rejected (higher cost) |
| **Option C (Brute Force)** | Shutdown `release_controller` | **10** | 3 of 3 (100%) | Rejected (2x higher cost) |
| **Option D (Incomplete)** | Revoke `deploy_token` alone | 2 | 2 of 3 (66%) | Rejected (artifact route open) |
| **Option E (Incomplete)** | Revoke `artifact_token` alone | 3 | 1 of 3 (33%) | Rejected (deploy routes open) |

---

## 4. Quickstart & Local Setup

### Prerequisites
- Docker Desktop with Linux Engine enabled
- Python 3.11+ (tested on Python 3.11.4 64-bit)

### 1. Start FalkorDB Container
```powershell
docker run -d --name cutline-falkordb --restart unless-stopped `
  -p 127.0.0.1:6379:6379 -p 127.0.0.1:3000:3000 `
  -v cutline_falkordb_data:/var/lib/falkordb/data `
  falkordb/falkordb:latest
```
- FalkorDB Browser UI: `http://localhost:3000`
- Database Client: `127.0.0.1:6379`

### 2. Set Up Virtual Environment & Dependencies
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Populate Demo Graph
```powershell
python seed.py
```

### 4. Run Automated Test Suite (33 Tests)
```powershell
pytest -v
```

### 5. Launch Streamlit Incident Console
```powershell
streamlit run app.py
```
Open `http://localhost:8501` in your browser.

---

## 5. Automated Test Suite Breakdown (33 Passed)

| Test File | Focus Area | Passing Tests |
| :--- | :--- | :--- |
| `tests/test_seed_integration.py` | Schema, node/edge counts, types, idempotency | 7 |
| `tests/test_graph_engine_integration.py` | Query 1 discovery, Query 2 centrality, Query 3 counterfactuals, Query 4 candidate costs | 8 |
| `tests/test_cut_set_calculator.py` | Combinatorial optimizer, cost-5 assertion, candidate cap, protected endpoints, edge cases | 15 |
| `tests/test_action_verification_integration.py` | Freshness revalidation, state mutation, post-action zero-path verification | 3 |
| **Total** | **Comprehensive Full System Coverage** | **33 / 33 PASSED** |

---

## 6. Authoritative Query Documentation

- **Query 1 (Bounded Multi-Hop Discovery):**
  `MATCH p = (src:Entity {id: $source_id})-[:ATTACK_STEP*1..8]->(target:Entity {criticality: 'crown_jewel'}) ...`
- **Query 2 (Betweenness Centrality):**
  `CALL algo.betweenness({nodeLabels: ['Entity'], relationshipTypes: ['ATTACK_STEP']}) YIELD node, score ...`
- **Query 3 (Counterfactual Verification):**
  `MATCH (src:Entity {id: $source_id}), (target:Entity {criticality: 'crown_jewel'}) OPTIONAL MATCH p = (src)-[:ATTACK_STEP*1..8]->(target) WHERE NONE(n IN nodes(p) WHERE n.id IN $severed_ids) RETURN count(p)`
- **Query 4 (Candidate Retrieval):**
  `MATCH (n:Entity) WHERE n.id IN $path_node_ids AND n.status <> 'disabled' AND n.criticality <> 'crown_jewel' AND n.id <> $source_id ...`
- **Query 5 (Containment Mutation):**
  `UNWIND $blocked_ids AS blocked_id MATCH (n:Entity {id: blocked_id}) SET n.status = 'disabled'` + deactivating incident `ATTACK_STEP` relationships.

---

## 7. AI Assistant Disclosure

This project was engineered following the anti-vibecoding specifications in `BUILD_INSTRUCTIONS.md`. All algorithms, Cypher queries, and tests were written, executed, and validated on live FalkorDB container instances. The LLM integration is strictly restricted to user intent routing and evidence summarization.

