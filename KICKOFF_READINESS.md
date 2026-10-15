# KICKOFF_READINESS.md — CUTLINE v2 Master Readiness & Pre-Kickoff Audit

## Executive Status
This document provides the authoritative pre-kickoff readiness record and specification audit for **CUTLINE v2** (WeMakeDevs / FalkorDB Graph Hacks hackathon, Track 01).

- **Current Local Timestamp:** October 13, 2026, 16:42 IST
- **Official Kickoff Timestamp:** October 15, 2026, 12:01 AM IST
- **Phase 1 Status:** **PASS** (16 nodes, 10 directed attack edges, 7 dependency edges, 3 directed attack paths of 5 hops each verified on live FalkorDB).
- **Rule 1 Compliance:** No application/Phase 2 implementation code has been added ahead of official kickoff.

---

## 1. Verified Environment & Container Status

### Host & Python Runtime
- **Host OS:** Windows (AMD64)
- **Active Environment:** `.\venv` (created via installed Python 3.11.4 64-bit; isolated from system Python 3.14).
- **Installed Packages (`pip show` verified):**
  - `falkordb`: **1.7.1**
  - `pydantic`: **2.14.1**
  - `streamlit`: **1.65.0**
  - `openai`: **3.29.0**
  - `pytest`: **9.1.1**
  - `python-dotenv`: **1.2.4**
- All dependencies import cleanly with zero warnings.

### Docker & FalkorDB Container
- **Docker CLI / Engine:** Docker Desktop 4.86.0 (236216), Docker Engine 29.7.2 (API version 1.55).
- **Container Details:**
  - Container Name: `cutline-falkordb`
  - Container Status: `running` (verified via `docker inspect --format '{{.State.Status}}' cutline-falkordb`)
  - Image Tag: `falkordb/falkordb:latest` (Image Digest: `sha256:107455e862a824e45e8e9f5a7fbfdf5e00a08b14e13eae2577c72fd9e3f59ba6`)
  - Persistent Volume: `cutline_falkordb_data` mounted to `/var/lib/falkordb/data`
  - Port Bindings: `127.0.0.1:6379->6379/tcp` (Redis protocol), `127.0.0.1:3000->3000/tcp` (FalkorDB Browser UI)
- **Harmless Connectivity Checks:**
  - FalkorDB Ping: `True` (`falkordb.FalkorDB(host='127.0.0.1', port=6379).connection.ping()`)
  - Browser UI Endpoint: HTTP `200 OK` (`http://127.0.0.1:3000`)

---

## 2. Current Repository Layout & File Manifest

```text
c:\Users\Aadrit\Desktop\we-make-devs-GRAPH_HACKS\
├── .env.example                     # Environment template (FalkorDB credentials, graph, hop bounds, LLM keys)
├── .gitignore                       # Git exclusions (venv, __pycache__, .env, .pytest_cache)
├── BUILD_INSTRUCTIONS.md            # Authoritative engineering specification
├── PRE_KICKOFF_READINESS.md         # Initial pre-kickoff environment discovery log
├── KICKOFF_READINESS.md             # This master audit and readiness document
├── pytest.ini                       # Pytest configuration (pythonpath = ., testpaths = tests)
├── requirements.txt                 # Pinned project dependencies
├── seed.py                          # Synthetic graph generator with live FalkorDB assertions
└── tests/
    └── test_seed_integration.py     # Live integration test suite for seed topology and constraints
```

### Git Secrets & Exclusion Audit
- Verified via `git check-ignore -v`:
  - `.env` -> IGNORED (prevents leaking OpenAI API keys or local settings)
  - `venv/` -> IGNORED
  - `__pycache__/` -> IGNORED
  - `.pytest_cache/` -> IGNORED
- Working branch: `main`. Clean repository state.

---

## 3. Phase 1 Acceptance Criteria & Observed Evidence

All Phase 1 requirements from `BUILD_INSTRUCTIONS.md` have been executed and verified against live FalkorDB:

1. **Live Database Connectivity:** Answers queries over port 6379.
2. **Node Count:** Exactly 16 `Entity` nodes with valid properties (`id`, `name`, `kind`, `criticality`, `cost`, `status`).
3. **Attack Edge Count:** Exactly 10 directed `ATTACK_STEP` relationships (`mechanism`, `active=true`, `evidence_id`).
4. **Dependency Edge Count:** Exactly 7 directed `DEPENDS_ON` relationships (`purpose`).
5. **Directed Attack Paths:** Exactly 3 active directed attack paths from `ci_runner` to `signing_key` within the 8-hop bound, each spanning 5 hops:
   - Path 1: `ci_runner` -> `artifact_token` -> `artifact_registry` -> `release_controller` -> `signer_role` -> `signing_key`
   - Path 2: `ci_runner` -> `deploy_token` -> `legacy_release_session` -> `release_controller` -> `signer_role` -> `signing_key`
   - Path 3: `ci_runner` -> `deploy_token` -> `production_deploy_role` -> `release_controller` -> `signer_role` -> `signing_key`
6. **Reseeding Determinism:** Multiple runs of `seed.py` cleanly clear and rebuild identical topology.
7. **Automated Test Results:**
   - Command: `.\venv\Scripts\pytest -v tests/test_seed_integration.py`
   - Output: `7 passed in 0.24s`

---

## 4. Phase 2 Specification & Query Compatibility Audit

A detailed review of `BUILD_INSTRUCTIONS.md` Section 6 ("Exact OpenCypher queries") against FalkorDB 1.7.1 client / server identified the following technical parameters:

### A. FalkorDB Client Parameter Serialization
- **Client Interface:** `Graph.query(q: str, params: Optional[Dict[str, object]] = None, timeout: Optional[int] = None)`
- **Header Mechanism:** `falkordb-py` builds a `CYPHER ...` header prepending parameters into the command buffer before sending over the Redis wire.
- **PowerShell Execution Note:** When invoking Python one-liners from PowerShell CLI, PowerShell will attempt to evaluate unescaped `$parameter` identifiers in double-quoted strings as PowerShell variables. In production code files (`graph_client.py`), Python string literals preserve `$param` cleanly without shell interference.
- **Cypher Parameter Reference:** Standard `$param` syntax within `.py` modules correctly binds to variables defined in the query parameter dictionary.

### B. Bounded Multi-Hop Discovery (Query 1)
- **Source & Target Definition:** Bounded to start at `$source_id` (`ci_runner`) and terminate at `criticality: 'crown_jewel'` (`signing_key`).
- **Traversal Scope:** Bounded to 1..8 directed `ATTACK_STEP` hops.
- **Filters:**
  - `ALL(r IN relationships(p) WHERE r.active = true)`
  - `ALL(n IN nodes(p) WHERE n.status <> 'disabled')`
- **Output:** Returns ordered node IDs, node names, node kinds, mechanisms, evidence IDs, and hop count.
- **Scope Note:** The specification explicitly notes this is bounded graph traversal over modeled attack relationships, not an exhaustive scan of real-world infrastructure.

### C. Native Centrality (`algo.betweenness`) (Query 2)
- **Invocation:**
  ```cypher
  CALL algo.betweenness({
      nodeLabels: ['Entity'],
      relationshipTypes: ['ATTACK_STEP']
  })
  YIELD node, score
  RETURN
      node.id AS id,
      node.name AS name,
      node.kind AS kind,
      score
  ORDER BY score DESC
  ```
- **Tested Server Output on Pinned Container:** Successfully returns 16 rows.
  - Top central node: `release_controller` (score: 12.0)
  - Second central node: `signer_role` (score: 7.0)
  - Tied 3rd/4th: `artifact_registry` (score: 4.0), `deploy_token` (score: 4.0)
- **Crucial Architectural Distinction:** Betweenness centrality identifies structural graph bridges, but **does not prove containment**. For example, `release_controller` has the highest centrality (12.0) but shutting it down costs 10, whereas revoking `deploy_token` (cost 2) and `artifact_token` (cost 3) severs all 3 paths at cost 5 despite lower individual centrality scores.

### D. Counterfactual & Post-Action Verification (Query 3)
- **Pre-action Counterfactual:** Supplies `$severed_ids = ['deploy_token', 'artifact_token']`. Evaluates:
  `NONE(n IN nodes(p) WHERE n.id IN $severed_ids)` -> Returns `remaining_path_count = 0`.
- **Single Token Test:** If only `artifact_token` is severed, remaining paths = 2. If only `deploy_token` is severed, remaining paths = 1.
- **Post-action Live Query:** Executed after real database mutation (`UNWIND $blocked_ids ... SET n.status = 'disabled'` and `SET r.active = false`) with `$severed_ids = []`. Must return `remaining_path_count = 0` to declare success.

### E. Candidate Retrieval & Endpoint Protection (Query 4)
- **Query:** Selects active nodes on discovered paths excluding `$source_id` and `crown_jewel`.
- **Live Costs Fetched from FalkorDB:**
  - `deploy_token`: cost 2
  - `artifact_token`: cost 3
  - `legacy_release_session`: cost 4
  - `production_deploy_role`: cost 6
  - `artifact_registry`: cost 7
  - `signer_role`: cost 8
  - `release_controller`: cost 10
- **Protection Guard:** `ci_runner` and `signing_key` are protected endpoints and must never be considered mitigation candidates.

---

## 5. Cut-Set Mathematics (Phase 3 Audit)

- **Algorithm Structure:** Pure deterministic combinatorial search implemented in `cut_set_calculator.py`.
- **Mathematical Invariant:** A set of candidate nodes $C$ is a valid vertex cut if for every discovered path $P$, $P \cap C \neq \emptyset$.
- **Cost Function:** $\sum_{c \in C} \text{cost}(c)$.
- **Deterministic Tie-Breaking:** Ranked by `(total_cost, len(selected_nodes), sorted(selected_node_ids))`.
- **Expected Optimum:**
  - Optimal Cut: `{"artifact_token", "deploy_token"}` (Cost: 2 + 3 = 5, Nodes: 2)
  - Controller Alternative: `{"release_controller"}` (Cost: 10, Nodes: 1) -> Valid cut, but suboptimal.
  - Signer Alternative: `{"signer_role"}` (Cost: 8, Nodes: 1) -> Valid cut, but suboptimal.
- **Candidate Cap:** Enforce $K \le 18$ candidates (up to $2^{18}-1 = 262,143$ subsets) to guarantee predictable sub-second computation without unbounded explosion.

---

## 6. Expected Submission Files & Roles

At kickoff, the full repository structure will be established as required by Section 2:

1. `graph_client.py`: FalkorDB client wrapper with reviewed parameterized queries.
2. `cut_set_calculator.py`: Pure deterministic Python combinatorial solver.
3. `logic.py`: Orchestration layer coordinating graph queries, candidate fetching, cut calculation, freshness verification, and simulation mutation.
4. `app.py`: Streamlit frontend, evidence display, human approval workflow, and optional LLM intent router/summarizer.
5. `tests/test_graph_engine_integration.py`: Integration tests for Phase 2 queries against FalkorDB.
6. `tests/test_cut_set_calculator.py`: Unit and integration tests for Phase 3 mathematics.
7. `tests/test_action_verification_integration.py`: End-to-end integration test of the approval and verification loop.
8. `README.md`: Master submission documentation.

---

## 7. Commands to Execute at Kickoff

When kickoff arrives, execute these commands in exact sequence:

```powershell
# 1. Activate Python 3.11 virtual environment
.\venv\Scripts\Activate.ps1

# 2. Confirm FalkorDB container is running
docker ps --filter "name=cutline-falkordb"

# 3. Re-verify Phase 1 acceptance gate
.\venv\Scripts\pytest -v tests/test_seed_integration.py

# 4. Proceed to Phase 2 implementation
# Implement graph_client.py and tests/test_graph_engine_integration.py
.\venv\Scripts\pytest -v tests/test_graph_engine_integration.py

# 5. Proceed to Phase 3 implementation
# Implement cut_set_calculator.py, logic.py, and tests/test_cut_set_calculator.py
.\venv\Scripts\pytest -v tests/test_cut_set_calculator.py

# 6. Proceed to Phase 4 implementation
# Implement app.py and tests/test_action_verification_integration.py
.\venv\Scripts\pytest -v tests/test_action_verification_integration.py
```

---

## 8. Docker & Dependency Troubleshooting Guide

1. **Docker Daemon Connection Dropped:**
   - Check status: `docker ps`
   - If pipe `//./pipe/dockerDesktopLinuxEngine` is missing, start Docker Desktop via:
     `Start-Process "C:\Users\Aadrit\AppData\Local\Programs\DockerDesktop\resources\com.docker.backend.exe"`
2. **Container Stopped:**
   - Restart container: `docker start cutline-falkordb`
3. **Graph State Reset:**
   - Run `.\venv\Scripts\python.exe seed.py` to restore pristine baseline.
4. **Missing Python Package:**
   - Re-verify virtual environment: `.\venv\Scripts\pip install -r requirements.txt`

