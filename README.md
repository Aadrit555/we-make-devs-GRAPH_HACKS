# TEZCATL — Obsidian Mirror Graph Containment Engine

[![FalkorDB](https://img.shields.io/badge/FalkorDB-Multi--Graph-orange)](https://www.falkordb.com/)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Pydantic](https://img.shields.io/badge/Validation-Pydantic%20v2-green)](https://pydantic.dev/)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-red)](https://streamlit.io/)
[![Tests](https://img.shields.io/badge/Tests-42%20Passed-brightgreen)](tests/)

> *"Multi-Hop Breach Discovery, Blast-Radius Calculus & Shadow-Graph Verification powered by FalkorDB"*

**TEZCATL** (named after the Aztec Lord of the Smoking Obsidian Mirror) is a pure-graph incident containment engine built for the **WeMakeDevs / FalkorDB Graph Hacks Hackathon (Track 01: Agents That Act on Connected Data)**.

TEZCATL scries a compromised CI/CD workload runner, traces all modeled directed attack paths to a production signing key (crown jewel) within an 8-hop bound, computes downstream operational blast radius dynamically via reverse multi-hop graph dependency traversal, verifies counterfactual containment in an isolated **Smoking Mirror sandbox** (`tezcatl_mirror`) without touching production, requires an explicit human authorization gate, applies the minimum-disruption cut to `prod_graph`, verifies 0 remaining paths, and generates a downloadable **Cryptographic Containment Audit Receipt** with pre/post SHA-256 state integrity hashes.

---

## 1. What TEZCATL Does and Does Not Do

### What TEZCATL Does
- **Obsidian Scrying Engine:** Traverses directed `ATTACK_STEP` relationships from `$source_id` to `crown_jewel` targets using strictly parameterized OpenCypher on live FalkorDB.
- **Structural Bottleneck Discovery:** Executes FalkorDB's native `algo.betweenness` procedure over directed relationships to pinpoint high-traffic bridge entities.
- **Dynamic Blast-Radius Calculus:** Dynamically computes operational disruption via reverse multi-hop dependency traversal (`MATCH (s:Service)-[:DEPENDS_ON*1..4]->(e:Entity)`), summing unique downstream `:Service` revenue impact scores (1–5) rather than relying on static node properties.
- **Deterministic Combinatorial Optimizer:** Computes the lowest-cost vertex cut that intersects 100% of discovered attack paths, proving mathematically that revoking both credentials (blast radius 5) beats shutting down the production controller (blast radius 10).
- **Smoking Mirror Multi-Graph Sandbox:** Uses FalkorDB's native `select_graph` feature to clone the topology into an isolated sandbox (`tezcatl_mirror`). Evaluates candidate severing and verifies 0 remaining paths in the shadow graph before mutating production.
- **Cryptographic Containment Receipt:** Generates an inspectable and downloadable JSON/Markdown audit receipt containing pre-mitigation and post-mitigation SHA-256 graph state hashes, spared high-centrality bottlenecks (`release_controller` spared, keeping `Checkout API`, `Billing Worker`, `Release Pipeline` online), and exact Cypher execution latencies.
- **Grounded LLM Layer:** Optional OpenAI SDK intent router and evidence summarizer strictly bounded to structured query evidence with zero hallucination.

### What TEZCATL Does Not Do
- **No Production Remediation:** All attack relationships, infrastructure assets, and impact costs are synthetic local demonstration artifacts. It does not touch real AWS, GitHub, or Kubernetes systems.
- **No LLM Calculation:** The LLM never writes Cypher, mutates graph state, or determines the optimal cut.
- **No Mock Databases or Silent Fallbacks:** All paths, costs, centrality scores, and verification counts originate from live queries against FalkorDB.

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

### 3. Populate TEZCATL Pristine Seed Graph
```powershell
python seed.py
```

### 4. Run Automated Test Suite (42 Tests)
```powershell
pytest -v
```

### 5. Launch TEZCATL Incident Command Console
```powershell
streamlit run app.py
```
Open `http://localhost:8501` in your browser.

---

## 5. Automated Test Suite Breakdown (42 Passed)

| Test File | Focus Area | Passing Tests |
| :--- | :--- | :--- |
| `tests/test_audit_hardening_integration.py` | Security regex, read-only segregation, telemetry, blast radius, mirror sandbox, audit receipt | 9 |
| `tests/test_graph_engine_integration.py` | Query 1 discovery, Query 2 centrality, Query 3 counterfactuals, candidate retrieval | 8 |
| `tests/test_cut_set_calculator.py` | Combinatorial optimizer, cost-5 assertion, candidate cap, protected endpoints, edge cases | 15 |
| `tests/test_action_verification_integration.py` | Freshness revalidation, state mutation, post-action zero-path verification | 3 |
| `tests/test_seed_integration.py` | Schema, node/edge counts, types, idempotency, path verification | 7 |
| **Total** | **Comprehensive Full System Coverage** | **42 / 42 PASSED** |

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
- **Query 6 (Blast-Radius Reverse Traversal):**
  `MATCH (s:Service)-[:DEPENDS_ON*1..4]->(e:Entity) WHERE e.id IN $candidate_ids RETURN e.id, count(DISTINCT s), sum(s.revenue_impact_score), collect(DISTINCT s.name)`
- **Query 7 (Mirror Sandbox Cloning):**
  Parameterized `UNWIND` node and edge replication into `db.select_graph("tezcatl_mirror")`.
- **Query 8 (Cryptographic State Hash):**
  Deterministic canonical SHA-256 fingerprinting of ordered nodes and active relationships.

---

## 7. AI Assistant Disclosure

This project was engineered following strict production anti-vibecoding specifications. All algorithms, Cypher queries, and tests were written, executed, and validated against live FalkorDB container instances. The LLM integration is strictly restricted to user intent routing and evidence summarization.

---

## 8. 120-Second Demo Video Walkthrough & Checklist

Follow this exact timeline when recording the 2-minute demonstration:

- **00:00 – 00:20 | Incident Context & Topology Controls (Column 1):**
  - Launch Streamlit console at `http://localhost:8501`.
  - Highlight the classification bar: `TEZCATL // Obsidian Mirror Graph Containment Engine`, live FalkorDB connection on `prod_graph` and `tezcatl_mirror`.
  - Show incident context: `ci_runner` compromised, protecting `signing_key` within $\le 8$ hops.
- **00:20 – 00:45 | Obsidian Scrying Engine (Column 2):**
  - Click **"RUN GRAPH DISCOVERY & CUT OPTIMIZER"**.
  - Show 3 active directed attack trajectories with hop-by-hop mechanisms and evidence IDs (`E-001` through `E-010`).
  - Show native `algo.betweenness` scores where `release_controller` scores highest (12.0).
  - Clarify the core insight: High centrality $\ne$ minimum-disruption cut.
  - Review live FalkorDB Query Inspector showing exact parameterized Cypher and execution latency in milliseconds.
- **00:45 – 01:10 | Dynamic Blast-Radius Calculus & Smoking Mirror Sandbox (Column 3):**
  - Show the Graph-Computed Blast Radius table: `deploy_token` = 2, `artifact_token` = 3, `release_controller` = 10.
  - Emphasize that costs are NOT static numbers; they are computed dynamically via reverse dependency traversal to downstream `:Service` nodes (`Checkout API`, `Billing Worker`, `Release Pipeline`).
  - Show the **Smoking Mirror Sandbox** side-by-side telemetry:
    - `prod_graph`: **3 Active Attack Paths** (Uncontained)
    - `tezcatl_mirror`: **0 Active Attack Paths** (Verified Contained in `< 50 ms`)
- **01:10 – 01:35 | Human Approval Gate & Production Commit:**
  - Check "I authorize committing the verified mirror cut to production."
  - Click **"COMMIT MIRROR CUT TO PRODUCTION"**.
  - Show live FalkorDB mutation on `prod_graph` and immediate re-verification confirming **0 remaining paths**.
- **01:35 – 02:00 | Cryptographic Containment Receipt:**
  - Expand the **TEZCATL Containment Audit Receipt**.
  - Show divergent pre-mitigation and post-mitigation SHA-256 graph integrity hashes.
  - Highlight spared high-centrality bottlenecks (`release_controller` kept online, preserving all downstream services).
  - Demonstrate one-click download of the receipt as JSON and Markdown.
