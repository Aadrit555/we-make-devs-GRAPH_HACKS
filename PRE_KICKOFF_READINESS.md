# PRE_KICKOFF_READINESS.md — CUTLINE v2 Preparation & Readiness Report

## Executive Summary
This document records the exact pre-kickoff environment readiness, dependency audit, Docker container verification, connectivity test outputs, and specification review for **CUTLINE v2**.

- **Current Local Timestamp:** October 13, 2026, 15:52 IST
- **Official Kickoff Timestamp:** October 15, 2026, 12:01 AM IST
- **Status:** **PRE-KICKOFF PREPARATION COMPLETE & VERIFIED.** Standing by for official kickoff before executing core submission phases.

---

## 1. Repository and Environment Status
- **Workspace:** `c:\Users\Aadrit\Desktop\we-make-devs-GRAPH_HACKS`
- **Git Branch:** `main` (clean baseline initialized, untracked development scaffolding prepared)
- **Git Protection:** `.gitignore` active, properly ignoring:
  - `venv/`
  - `__pycache__/`
  - `*.py[cod]`
  - `.env` (protecting API keys / credentials)
  - `.pytest_cache/`
- **Environment Configuration:** `.env.example` created with template keys:
  ```dotenv
  FALKORDB_HOST=127.0.0.1
  FALKORDB_PORT=6379
  FALKORDB_GRAPH=cutline_demo
  CUTLINE_SOURCE_ID=ci_runner
  CUTLINE_TARGET_ID=signing_key
  CUTLINE_MAX_HOPS=8
  OPENAI_API_KEY=
  OPENAI_MODEL=gpt-4o-mini
  ```

---

## 2. Docker & FalkorDB Container Verification

### Execution Verification Commands & Observed Results:

#### A. Docker CLI and Engine
```powershell
docker version
```
**Output:**
```text
Client:
 Version:           29.7.2
 API version:       1.55
 Go version:        go1.26.5
 OS/Arch:           windows/amd64
 Context:           desktop-linux

Server: Docker Desktop 4.86.0 (236216)
 Engine:
  Version:          29.7.2
  API version:      1.55
  OS/Arch:          linux/amd64
```

#### B. FalkorDB Container Inspection
```powershell
docker ps -a --filter "name=cutline-falkordb"
docker inspect --format '{{.State.Status}}' cutline-falkordb
docker volume ls
```
**Output:**
```text
CONTAINER ID   IMAGE                      COMMAND                  CREATED       STATUS       PORTS                                                NAMES
7b98794ee885   falkordb/falkordb:latest   "/var/lib/falkordb/b…"   2 hours ago   Up 2 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:6379->6379/tcp   cutline-falkordb

Status: running

DRIVER    VOLUME NAME
local     cutline_falkordb_data
```

#### C. Container Log Tail
```powershell
docker logs --tail 30 cutline-falkordb
```
**Output Highlights:**
```text
Redis version=8.10.2, bits=64, Running mode=standalone, port=6379.
Module 'graph' loaded from /var/lib/falkordb/bin/falkordb.so
Server initialized, Ready to accept connections tcp
▲ Next.js 16.3.8 (FalkorDB Browser)
- Local: http://localhost:3000
- Network: http://0.0.0.0:3000
✓ Ready
```

---

## 3. FalkorDB Live Connectivity & Browser Endpoint Tests

### A. Harmless Database Ping Test
Command:
```powershell
.\venv\Scripts\python.exe -c "from falkordb import FalkorDB; db = FalkorDB(host='127.0.0.1', port=6379); print('FalkorDB Ping:', db.connection.ping())"
```
**Output:**
```text
FalkorDB Ping: True
```

### B. FalkorDB Browser UI Endpoint
Command:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:3000" -UseBasicParsing | Select-Object StatusCode, StatusDescription
```
**Output:**
```text
StatusCode StatusDescription
---------- -----------------
       200 OK
```

---

## 4. Python Environment & Installed Dependency Versions

### Python Installation Audit:
- System Python: `Python 3.14.3` (Note: builds older C-extensions from source; MinGW GCC 6.3 incompatible with NumPy 1.26 C-extensions).
- Dedicated Project Environment: Created at `.\venv` using installed **Python 3.11.4 (64-bit)**.
- Verified Installed Package Versions:
  - `falkordb`: **1.7.1**
  - `pydantic`: **2.14.1**
  - `streamlit`: **1.65.0**
  - `openai`: **3.29.0**
  - `pytest`: **9.1.1**
  - `python-dotenv`: **1.2.4**

All packages and their transitives (`pandas`, `altair`, `pydantic-core`, `redis`, `anyio`) import cleanly without errors or warnings.

---

## 5. Audit of BUILD_INSTRUCTIONS.md & Implementation Risks

A complete review of the build specification identified the following key architectural boundaries and implementation considerations:

1. **Native Centrality (`algo.betweenness`) vs. Directed Containment Proof:**
   - Centrality indicates structural vertex prominence across the graph, but does **not** prove attack containment.
   - Proof of containment is established **only** by the directed traversal query (Query 1) and the zero-path verification query (Query 3).
2. **Pre-action vs. Post-action Verification Discrepancy:**
   - Pre-action calculation computes counterfactual reachability (`NONE(n IN nodes(p) WHERE n.id IN $severed_ids)`).
   - Post-action verification must execute a **fresh query** against the actual mutated graph state with `$severed_ids = []` after updating `Entity.status = 'disabled'` and `ATTACK_STEP.active = false`.
3. **Endpoint Protection in Candidate Cut Formulation:**
   - Source node (`ci_runner`) and Crown-jewel target (`signing_key`) must be strictly excluded from eligible cut candidates to prevent trivial/invalid containment solutions.
4. **State Freshness & Race Protection:**
   - Before applying the simulated action upon human approval, the system must verify graph freshness. If graph state changed between calculation and approval, mutation must be aborted and re-planned.
5. **LLM Boundary & Anti-Vibecoding Contract:**
   - The LLM must strictly function as an intent classifier and natural-language summarizer of structured evidence.
   - The LLM has zero authority to generate Cypher, mutate state, or calculate cuts.

---

## 6. Kickoff Execution Checklist (At Hackathon Start)

Upon arrival of the official kickoff time (October 15, 2026, 12:01 AM IST):

- [ ] **Phase 1: Seed Execution & Verification**
  - Run `python seed.py` to populate pristine demonstration topology into `cutline_demo`.
  - Execute `pytest tests/test_seed_integration.py` to confirm 16 nodes, 10 attack edges, 7 dependency edges, and typing.
- [ ] **Phase 2: Live Graph Engine Implementation**
  - Implement Pydantic domain models (`AttackPath`, `MitigationCandidate`, `CutPlan`, `CentralityScore`).
  - Implement `graph_client.py` wrapping the 5 exact OpenCypher parameterized queries.
  - Implement and pass `tests/test_graph_engine_integration.py` (3 paths of 5 hops, live centrality execution, live candidate costs, counterfactual zero check).
- [ ] **Phase 3: Deterministic Cut-Set Engine**
  - Implement `cut_set_calculator.py` with deterministic ranking `(total_cost, num_nodes, sorted_ids)`.
  - Implement `logic.py` service layer with freshness check and revalidation.
  - Implement and pass `tests/test_cut_set_calculator.py` proving the cost-5 cut `{deploy_token, artifact_token}` beats the cost-10 controller shutdown.
- [ ] **Phase 4: Streamlit Frontend & LLM Router**
  - Implement `app.py` with clean evidence display, centrality table, human approval modal/button, and real-time counterfactual / post-action verification display.
  - Implement `tests/test_action_verification_integration.py` validating the full mutation and zero-path post-verification loop.
- [ ] **Final Submission Gate**
  - Run all integration and unit test suites from clean state.
  - Finalize `README.md` with tested commands, architecture diagrams, and AI-assistant disclosure.

