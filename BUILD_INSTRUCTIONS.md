# BUILD_INSTRUCTIONS.md — CUTLINE v2 Master Build Instructions

## Mission

Build **CUTLINE v2**, a working graph-native attack-path containment planner for the WeMakeDevs/FalkorDB Graph Hacks hackathon, Track 01: Agents That Act on Connected Data.

CUTLINE investigates a compromised CI/CD runner, discovers every modeled directed attack path to a production signing key within the configured eight-hop bound, calculates the least-cost available node-removal plan that intersects every discovered path, asks a human to approve the plan, applies the simulated containment to FalkorDB, and runs a new query to verify that no modeled active path remains.

This is a synthetic, local demonstration. Do not connect to or modify real AWS, GitHub, Kubernetes, IAM, KMS, or production systems. Label simulated actions honestly.

You are acting as a rigorous backend systems engineer, graph engineer, test engineer, and only then a UI developer. The UI is secondary. Build back-to-front and prove each layer before proceeding.

---

## 1. Anti-vibecoding pledge — mandatory

Before writing code, read this entire file and inspect the repository. Then implement the system in the exact phase order below.

### Forbidden shortcuts

- Do not use Python `pass` statements, `# TODO` comments, placeholder implementations, fake success returns, or functions that claim to work without performing the underlying operation.
- Do not build the UI first.
- Do not put hardcoded graph nodes, paths, centrality scores, costs, cut plans, path counts, verification results, or fake database response objects in the UI layer.
- Do not substitute an in-memory graph, static JSON, a Python dictionary posing as a database, a vector store, or canned fixture output for live FalkorDB queries.
- Do not create a fake fallback that claims a database query succeeded when FalkorDB is unavailable.
- Do not let the LLM write arbitrary Cypher, invent attack relationships, calculate the authoritative cut, approve a mitigation, mutate graph state, or declare verification successful.
- Do not skip tests, swallow exceptions, silence a failing phase, or continue to the next phase with red tests.
- Do not hardcode the expected result into the application path. Expected values may appear in tests as assertions, never as values returned by production functions.
- Do not catch broad exceptions merely to return empty results. Surface failures with a clear error and preserve the failed state.
- Do not use a precomputed screenshot or front-end graph diagram as evidence of discovery. Any displayed path, node, edge, cost, centrality score, selected action, and verification count must be grounded in live database responses or in deterministic calculations over live database results.

### Required engineering behavior

1. Use the local Docker FalkorDB instance as the source of truth.
2. Execute real parameterized OpenCypher queries using the official `falkordb` Python client.
3. Use Pydantic models to validate API/domain inputs and outputs.
4. Implement the cut-set calculation as a pure deterministic Python function that consumes actual discovered paths and mitigation candidates loaded from FalkorDB.
5. Keep the LLM as an optional intent router and evidence summarizer. It must not perform graph mathematics or generate authoritative facts.
6. Add tests at every layer. Run them and inspect their actual output before marking a phase complete.
7. If a FalkorDB query or procedure does not work against the pinned image, inspect the current official FalkorDB documentation and adapt the real query. Do not replace it with a mock or quietly remove the capability.
8. Prefer a smaller working system to a beautiful incomplete one.

### Definition of “live data”

Application data shown to the user must be sourced from a live Cypher query against the configured local FalkorDB graph. Static labels, explanatory copy, column names, and buttons are allowed. Node properties, edges, attack paths, costs, centrality scores, proposed plans, and post-action status must not be supplied by hardcoded UI objects. The deterministic plan is allowed to be computed in Python, but its paths and candidate costs must first come from FalkorDB.

The seed script may contain the fixed synthetic seed records below because its explicit job is to create the demo graph. The UI must never use those seed arrays as its read source.

---

## 2. Product contract and architecture

### Required end-to-end flow

1. Read the incident source and crown-jewel target from the live graph.
2. Run bounded directed path discovery against FalkorDB.
3. Read eligible candidate nodes and their `cost` properties from FalkorDB.
4. Run native FalkorDB betweenness centrality and display the actual returned scores.
5. Run the deterministic minimum-cost vertex-cut search over the discovered paths and live candidate costs.
6. Display the discovered paths, actual centrality result, candidate cost comparison, selected containment plan, and scope warning.
7. Require an explicit human approval click.
8. Revalidate the plan against the current graph before applying it. If the graph has changed or any path remains under the proposed cut, refuse to apply and require a new plan.
9. In this synthetic demo only, mark selected target entities disabled and affected `ATTACK_STEP` relationships inactive in FalkorDB.
10. Run a fresh counterfactual/post-action query against the actual mutated graph.
11. Report success only if the new query returns zero active paths within the stated eight-hop graph scope. Otherwise show verification failure.

### Architecture boundaries

- **FalkorDB:** graph state, directed attack relationships, query-backed paths, entity costs/status, native centrality results, and verification queries.
- **Python graph client:** owns reviewed, parameterized Cypher query strings and maps query results into typed values.
- **Cut-set calculator:** pure deterministic mathematics; no UI code, no LLM calls, and no database connection inside the core algorithm.
- **Logic/service layer:** fetches live paths and candidate entities, invokes the calculator, validates freshness, and applies the approved simulated action.
- **LLM:** may classify a natural-language request into a small validated enum and summarize returned evidence. The LLM has no authority over the graph or the result.
- **Streamlit:** calls backend functions and renders returned data. No database query strings or graph business logic in the UI layer.

### Required repository layout

Create this structure unless the existing repository already has a clear equivalent. Do not duplicate modules just to satisfy naming preferences.

```text
.
├── BUILD_INSTRUCTIONS.md
├── README.md
├── requirements.txt
├── .env.example
├── .gitignore
├── seed.py
├── graph_client.py
├── cut_set_calculator.py
├── logic.py
├── app.py
└── tests/
    ├── test_seed_integration.py
    ├── test_graph_engine_integration.py
    ├── test_cut_set_calculator.py
    └── test_action_verification_integration.py
```

`cut_set_calculator.py` must contain the pure combinatorial engine. `logic.py` must contain service orchestration over `graph_client.py` and `cut_set_calculator.py`. Avoid duplicate implementations.

---

## 3. Strict technology stack

- **Python:** 3.11 or newer; use type hints throughout.
- **Database:** local Docker instance of FalkorDB with the Browser UI enabled.
- **Graph client:** official `FalkorDB` Python package, imported as `from falkordb import FalkorDB`.
- **Validation:** Pydantic v2 models for entities, discovered paths, mitigation candidates, plans, and verification results.
- **UI:** Streamlit.
- **LLM SDK:** OpenAI Python SDK, used only for optional intent classification and evidence-grounded summaries. Use environment variables for the API key/model. Do not require an API key to run graph discovery, cut calculation, approval simulation, and verification.
- **Tests:** pytest.

Keep dependencies small. Do not add LangChain, vector databases, orchestration frameworks, graph visualization libraries, or multi-agent libraries unless a concrete tested requirement proves one is necessary. Prefer the OpenAI SDK directly over introducing a second tool framework.

Create a `requirements.txt` with compatible version bounds for `FalkorDB`, `pydantic` v2, `streamlit`, `openai`, and `pytest`. Pin the exact versions that you actually test before submission and document them. Do not claim a dependency works until it installs in the project's Python environment.

Suggested environment variables:

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

An empty `OPENAI_API_KEY` must not prevent deterministic graph operation. In this situation, show that the LLM explanation is unavailable and use an explicitly labeled deterministic summary assembled from the live backend result. Never imply an LLM was used if it was not.

---

## 4. FalkorDB Docker setup

Use this command to start the local server and Browser UI with persistent storage. Bind ports to loopback for local development:

```bash
docker run -d --name cutline-falkordb --restart unless-stopped -p 127.0.0.1:6379:6379 -p 127.0.0.1:3000:3000 -v cutline_falkordb_data:/var/lib/falkordb/data falkordb/falkordb:latest
```

- Browser UI: `http://localhost:3000`
- FalkorDB client: `127.0.0.1:6379`
- Graph name: `cutline_demo`
- Persistent Docker volume: `cutline_falkordb_data`

Check whether the container already exists before starting another one. If it exists but is stopped, start it instead of creating a duplicate. Do not delete the named volume during normal development. The seed script may reset nodes inside the dedicated `cutline_demo` graph, but it must not delete other graphs or volumes.

After confirming the demo works, record the tested image tag/digest in the README. Do not leave the submission dependent on whatever `latest` happens to point at later.

---

## 5. Exact data model

### Node label and properties

All graph entities use the `Entity` label with these required properties:

- `id`: unique string identifier.
- `name`: readable display name.
- `kind`: workload, credential, iam_role, registry, service, key, session, artifact, cluster, host, or trust_binding.
- `criticality`: low, medium, high, critical, or crown_jewel.
- `cost`: integer impact cost if the entity is disabled. Lower cost means less modeled disruption. It is a synthetic score, not dollars or a production metric.
- `status`: active, compromised, or disabled.

### Relationship types

`ATTACK_STEP` is a **directed** relationship and must contain:

- `mechanism`: text explaining the modeled mechanism.
- `active`: boolean indicating whether the edge currently represents an active modeled route.
- `evidence_id`: stable synthetic evidence reference.

`DEPENDS_ON` is a directed operational-dependency relationship with:

- `purpose`: text describing the dependency.

Do not use `DEPENDS_ON` for attacker reachability. All CUTLINE attack-path discovery and verification queries must traverse `ATTACK_STEP` only.

### Seed graph: exact entity records

Use these records in `seed.py`. Do not alter the IDs or costs without updating the tests and explaining the change.

```python
NODES = [
    {"id": "ci_runner", "name": "GitHub Actions CI Runner", "kind": "workload", "criticality": "high", "cost": 10, "status": "compromised"},
    {"id": "runner_host", "name": "Ephemeral Runner Host", "kind": "host", "criticality": "medium", "cost": 9, "status": "active"},
    {"id": "deploy_token", "name": "Production Deploy Credential", "kind": "credential", "criticality": "high", "cost": 2, "status": "active"},
    {"id": "production_deploy_role", "name": "Production Deploy IAM Role", "kind": "iam_role", "criticality": "high", "cost": 6, "status": "active"},
    {"id": "artifact_token", "name": "Artifact Publish Credential", "kind": "credential", "criticality": "high", "cost": 3, "status": "active"},
    {"id": "artifact_registry", "name": "Private Artifact Registry", "kind": "registry", "criticality": "high", "cost": 7, "status": "active"},
    {"id": "release_controller", "name": "Production Release Controller", "kind": "service", "criticality": "critical", "cost": 10, "status": "active"},
    {"id": "signer_role", "name": "Release Signing IAM Role", "kind": "iam_role", "criticality": "critical", "cost": 8, "status": "active"},
    {"id": "signing_key", "name": "Production Signing Key", "kind": "key", "criticality": "crown_jewel", "cost": 9999, "status": "active"},
    {"id": "legacy_release_session", "name": "Legacy Release Session", "kind": "session", "criticality": "high", "cost": 4, "status": "active"},
    {"id": "build_artifact", "name": "Signed Release Artifact", "kind": "artifact", "criticality": "high", "cost": 6, "status": "active"},
    {"id": "production_cluster", "name": "Production Kubernetes Cluster", "kind": "cluster", "criticality": "critical", "cost": 9, "status": "active"},
    {"id": "audit_service", "name": "Release Audit Service", "kind": "service", "criticality": "medium", "cost": 5, "status": "active"},
    {"id": "approval_service", "name": "Release Approval Service", "kind": "service", "criticality": "high", "cost": 5, "status": "active"},
    {"id": "deployment_manifest", "name": "Production Deployment Manifest", "kind": "artifact", "criticality": "high", "cost": 5, "status": "active"},
    {"id": "runner_oidc_binding", "name": "Runner OIDC Trust Binding", "kind": "trust_binding", "criticality": "high", "cost": 6, "status": "active"},
]
```

### Seed graph: exact directed attack edges

```python
ATTACK_EDGES = [
    {"source": "ci_runner", "target": "deploy_token", "mechanism": "Compromised process can access deploy credential", "active": True, "evidence_id": "E-001"},
    {"source": "deploy_token", "target": "production_deploy_role", "mechanism": "Credential permits production role assumption", "active": True, "evidence_id": "E-002"},
    {"source": "production_deploy_role", "target": "release_controller", "mechanism": "Role can invoke production release", "active": True, "evidence_id": "E-003"},
    {"source": "ci_runner", "target": "artifact_token", "mechanism": "Compromised runner can access registry credential", "active": True, "evidence_id": "E-004"},
    {"source": "artifact_token", "target": "artifact_registry", "mechanism": "Credential has artifact publish permission", "active": True, "evidence_id": "E-005"},
    {"source": "artifact_registry", "target": "release_controller", "mechanism": "Controller consumes registry artifacts", "active": True, "evidence_id": "E-006"},
    {"source": "deploy_token", "target": "legacy_release_session", "mechanism": "Credential can reach a legacy release session", "active": True, "evidence_id": "E-007"},
    {"source": "legacy_release_session", "target": "release_controller", "mechanism": "Legacy session can invoke production release", "active": True, "evidence_id": "E-008"},
    {"source": "release_controller", "target": "signer_role", "mechanism": "Release controller can request signing", "active": True, "evidence_id": "E-009"},
    {"source": "signer_role", "target": "signing_key", "mechanism": "Signing role can use production key", "active": True, "evidence_id": "E-010"},
]
```

### Seed graph: exact operational dependencies

```python
DEPENDENCIES = [
    {"source": "ci_runner", "target": "runner_host", "purpose": "runs_on"},
    {"source": "ci_runner", "target": "runner_oidc_binding", "purpose": "requests_federated_identity"},
    {"source": "release_controller", "target": "build_artifact", "purpose": "consumes_artifact"},
    {"source": "release_controller", "target": "production_cluster", "purpose": "deploys_to"},
    {"source": "release_controller", "target": "audit_service", "purpose": "emits_audit_events"},
    {"source": "release_controller", "target": "approval_service", "purpose": "requires_approval"},
    {"source": "artifact_registry", "target": "deployment_manifest", "purpose": "stores_release_manifest"},
]
```

### Required seed behavior

`seed.py` must:

1. Connect to `127.0.0.1:6379` using the official client.
2. Select graph `cutline_demo`.
3. Reset only the nodes and relationships in that graph, with a clear warning in the script that this is destructive to the demo graph.
4. Populate nodes, `ATTACK_STEP` relationships, and `DEPENDS_ON` relationships with parameterized queries.
5. Query and assert the live counts: 16 `Entity` nodes, 10 `ATTACK_STEP` relationships, and 7 `DEPENDS_ON` relationships.
6. Exit non-zero with a useful error if FalkorDB is unavailable or any assertion fails.
7. Never feed the arrays directly to Streamlit. They are seed inputs only.

Expected initial attack topology: exactly three distinct directed paths from `ci_runner` to `signing_key` within eight hops. All three share `release_controller` and `signer_role`. Two paths include `deploy_token`, while the artifact route includes `artifact_token`. Disabling both `deploy_token` and `artifact_token` must sever all three paths at a total modeled cost of 5. Disabling `release_controller` is also a valid cut at cost 10. `signer_role` is a valid single-node cut at cost 8, so the optimal cost remains 5.

---

## 6. Exact OpenCypher queries

Implement these query strings in `graph_client.py`. Use parameters instead of interpolating IDs or lists into query text. Keep query strings out of `app.py`.

### Query 1 — Bounded directed multi-hop discovery

Input: `$source_id`, with max path length of eight hops.

```cypher
MATCH p =
    (src:Entity {id: $source_id})
    -[:ATTACK_STEP*1..8]->
    (target:Entity {criticality: 'crown_jewel'})
WHERE ALL(r IN relationships(p) WHERE r.active = true)
  AND ALL(n IN nodes(p) WHERE n.status <> 'disabled')
RETURN
    [n IN nodes(p) | n.id] AS node_ids,
    [n IN nodes(p) | n.name] AS node_names,
    [n IN nodes(p) | n.kind] AS node_kinds,
    [r IN relationships(p) | r.mechanism] AS mechanisms,
    [r IN relationships(p) | r.evidence_id] AS evidence_ids,
    length(p) AS hops
ORDER BY hops ASC
```

Do not add a `LIMIT` that silently truncates results. This graph is deliberately small. If a query timeout or result cap is needed for safety, represent a truncated result as incomplete and do not let the application call it exhaustive. The initial seed must return three paths.

### Query 2 — Native FalkorDB betweenness centrality

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

Execute this as a real database procedure. Validate it against the actual image version during Phase 2. If the installed release has a different documented procedure signature, adapt the query to that official signature, add a test, and document the change. Never fake or hardcode the scores. The centrality score is structural context only; it does not prove that a containment action is effective. The directed path queries and cut verification supply that proof.

### Query 3 — Counterfactual verification / zero-path check

Inputs: `$source_id`, `$severed_ids`. The `severed_ids` parameter is the list of node IDs that a candidate plan would disable.

```cypher
MATCH
    (src:Entity {id: $source_id}),
    (target:Entity {criticality: 'crown_jewel'})
OPTIONAL MATCH p =
    (src)-[:ATTACK_STEP*1..8]->(target)
WHERE ALL(r IN relationships(p) WHERE r.active = true)
  AND ALL(n IN nodes(p) WHERE n.status <> 'disabled')
  AND NONE(n IN nodes(p) WHERE n.id IN $severed_ids)
RETURN count(p) AS remaining_path_count
```

The pre-action counterfactual call supplies the candidate node IDs. The actual post-action verification call supplies an empty list after selected entities have been marked disabled and their incident attack edges inactive. The post-action query must execute against FalkorDB after the state mutation. No predicted result may be reused as the actual result.

If the server rejects a language construct, consult the pinned release's official OpenCypher documentation, adapt it, and preserve the same semantics. Write an integration test against the live container to prove the query returns the expected result.

### Query 4 — Read eligible cut candidates and costs from FalkorDB

Use the current path node IDs to fetch actual entity records. Do not derive candidate costs from the Python seed constants.

```cypher
MATCH (n:Entity)
WHERE n.id IN $path_node_ids
  AND n.status <> 'disabled'
  AND n.criticality <> 'crown_jewel'
  AND n.id <> $source_id
RETURN
    n.id AS id,
    n.name AS name,
    n.kind AS kind,
    n.criticality AS criticality,
    n.cost AS cost,
    n.status AS status
ORDER BY cost ASC, id ASC
```

The implementation must decide which returned entities are eligible cut candidates. In the demo, any non-source, non-crown-jewel active path node with a nonnegative `cost` can be considered a candidate. Do not include the source or crown jewel as a candidate because the action must protect the starting incident identity and target asset rather than “solve” containment by removing either endpoint.

### Query 5 — Actual action mutation

After the human clicks Approve, validate that the proposed IDs are the same server-side plan that was shown and that the pre-action recheck still passes. In this synthetic demo, mark chosen nodes disabled:

```cypher
UNWIND $blocked_ids AS blocked_id
MATCH (n:Entity {id: blocked_id})
SET n.status = 'disabled'
RETURN collect(n.id) AS disabled_ids, count(n) AS updated_count
```

Mark incident modeled attack relationships inactive while retaining their evidence fields:

```cypher
MATCH (a:Entity)-[r:ATTACK_STEP]->(b:Entity)
WHERE a.id IN $blocked_ids OR b.id IN $blocked_ids
SET r.active = false
RETURN count(r) AS updated_edge_count
```

This pattern follows each directed relationship once and marks every attack relationship incident to a selected node, whether the selected node is the start or end of the edge. The directed edge itself is not reversed or deleted. Validate the actual counts and query output before reporting the action as applied.

---

## 7. Deterministic cut-set engine requirements

Implement the algorithm in `cut_set_calculator.py` as a pure function. It must have no FalkorDB client dependency, no Streamlit imports, and no LLM calls.

### Data models

Use Pydantic models (or typed dataclasses plus Pydantic validation at boundaries) for:

- `AttackPath`: ordered node IDs, node names, relationship mechanisms, evidence IDs, and hop count.
- `MitigationCandidate`: target node ID, name, kind, nonnegative integer `cost`, and status.
- `CutPlan`: chosen node IDs, total cost, all discovered path count, IDs of paths covered, and a deterministic explanation generated from the real result.

Reject invalid costs, duplicate IDs, malformed paths, and plans that target the source or crown-jewel node.

### Required algorithm

Input:

- All distinct paths from Query 1, as ordered node-ID sequences.
- Eligible candidate node records and their costs from Query 4.
- Source ID and crown-jewel target IDs.

Algorithm:

1. Normalize paths into sets for intersection testing but preserve original ordered paths for evidence and display.
2. Validate that every candidate cost is a nonnegative integer.
3. Build the candidate node set from the live node records that occur on at least one discovered path, excluding source and target IDs.
4. For each candidate subset in increasing subset size, compute the sum of the node costs.
5. A subset is a valid cut if every discovered path contains at least one selected node. Formally, for every path `P`, `P ∩ selected_nodes` must be non-empty.
6. Rank valid cuts by `(total_cost, number_of_nodes, sorted_node_ids)` so the output is deterministic.
7. Return the lowest-cost valid cut with its cost, selected targets, covered path IDs/count, and scope metadata.
8. If no valid cut exists, raise a domain error and do not recommend a false action.
9. Enforce a reasonable candidate cap (18 distinct eligible nodes for the exhaustive demo engine). If the cap is exceeded, fail with a clear message or implement a correctly tested minimum-cut algorithm; do not launch an unbounded exponential search.
10. Do not report “globally optimal” without stating the search scope. The exact claim is: “minimum-cost cut over the available candidate nodes and paths returned by the current query, bounded to eight hops.”

The action cost comes from the `Entity.cost` property fetched live from FalkorDB. There must be no second hardcoded costs table in `logic.py` or `app.py`.

### Mandatory seed-specific assertions

Against the live seeded database, the cut engine must assert all of the following:

- Query 1 returns exactly 3 distinct attack paths before containment.
- Candidate costs for `deploy_token`, `artifact_token`, and `release_controller` are fetched from FalkorDB and equal 2, 3, and 10 respectively.
- The selected cut is exactly `{"deploy_token", "artifact_token"}`.
- The resulting total modeled cost is exactly `5`.
- `release_controller` alone is a valid cut of cost `10` but is not selected as the optimum.
- Selecting only `artifact_token` leaves two paths; selecting only `deploy_token` leaves one path.
- The cut set intersects every discovered path.
- The counterfactual query with the selected cut returns `remaining_path_count = 0`.

These assertions belong in automated tests and the backend. The UI must display the computed result, not inject these expected values.

### Complexity and scope

Exhaustive candidate enumeration examines up to `2^K - 1` non-empty subsets for `K` candidate nodes. With `K <= 18`, that is at most 262,143 subsets and is acceptable for this small, bounded demonstration. The app must make the cap explicit and refuse to run an unbounded search. For larger graphs, investigate a weighted vertex-cut reduction using node splitting and a max-flow/min-cut solver, but do not add an untested dependency during the minimum viable build.

---

## 8. Sequential build phases — do not skip or reorder

**Rule:** Do not begin the next phase until every exit condition in the current phase passes. If a phase fails, diagnose the actual failure and fix it. Do not produce a fake result, downgrade the test, or skip the phase. At the end of each phase, report the commands run, observed test output, files created, and any remaining issue.

### Phase 1 — Database and seed

Tasks:

1. Inspect the environment and repository before changing files.
2. Confirm Docker is installed and running.
3. Start or reuse the local FalkorDB container using the command in Section 4.
4. Verify the server is reachable through the Python client.
5. Create `requirements.txt` and create/activate a Python 3.11+ environment.
6. Implement `seed.py` from the exact node and edge records above using parameterized Cypher.
7. Create `tests/test_seed_integration.py` that connects to live FalkorDB and queries the graph counts.
8. Run `python seed.py` and the integration test.

Exit conditions — all must pass:

- FalkorDB answers a real query.
- `cutline_demo` contains 16 `Entity` nodes, 10 `ATTACK_STEP` relationships, and 7 `DEPENDS_ON` relationships.
- Required properties are present and correctly typed.
- Reseeding is deterministic and does not affect other graphs.
- A connection failure returns a clear failure and nonzero command exit; it does not fake success.

Do not create Streamlit UI in this phase.

### Phase 2 — Live graph engine

Tasks:

1. Implement Pydantic models for query results.
2. Create `graph_client.py` with connection setup, health check, path discovery, centrality, candidate-node/cost retrieval, pre-action counterfactual verification, mutation, and actual post-action verification functions.
3. Store all Cypher in `graph_client.py`; keep query parameters separate from query strings.
4. Create `tests/test_graph_engine_integration.py` against the real local database.
5. Test actual query results, not fabricated fixtures.

Exit conditions — all must pass:

- Path discovery returns exactly three paths of five hops each on the pristine seed.
- Every returned path starts at `ci_runner` and ends at `signing_key`.
- Paths show the actual node IDs, names, mechanisms, and evidence IDs stored in FalkorDB.
- The native betweenness procedure runs successfully and returns live node/score rows. If the official procedure signature for the pinned image differs, adapt it and test the actual result.
- Candidate costs are read from FalkorDB and match the seeded properties.
- Counterfactual verification returns zero for the candidate set `{deploy_token, artifact_token}` and a positive count when only one of those two nodes is excluded.
- Query failures are surfaced, not translated into empty lists.

Do not implement the Streamlit UI in this phase.

### Phase 3 — Mathematics and action validation

Tasks:

1. Implement the exact cut-set algorithm in `cut_set_calculator.py`.
2. Implement the service function in `logic.py` to acquire live graph data and call the pure calculator.
3. Add fast unit tests for algorithm invariants and a live integration test that feeds Phase 2's returned paths and costs to the engine.
4. Test tie-breaking, invalid costs, source/target protection, one missing path, one surviving path, candidate-cap enforcement, and the no-solution case.
5. Do not move cut math into Streamlit or the LLM.

Exit conditions — all must pass:

- Live paths and live costs produce the cut `{deploy_token, artifact_token}` at total cost 5.
- The cost-10 controller shutdown is recognized as valid but not optimal.
- A single token revocation is rejected as incomplete.
- Every selected cut is checked against every returned path.
- The engine is deterministic across repeated executions.
- No LLM API key is required for the tests.

Do not begin the UI until this phase is green.

### Phase 4 — Agent and UI

Tasks:

1. Build a compact Streamlit interface that calls backend/service functions only.
2. Provide a clear button to investigate; show live returned paths and evidence.
3. Show the live native centrality result with a short explanation that centrality is structural context, not containment proof.
4. Show candidate mitigations and costs fetched from FalkorDB, plus the computed cut plan and per-path coverage.
5. Display the hop bound and the warning that results are limited to the current modeled graph.
6. Require a user approval button for the proposed simulated action.
7. Before mutation, re-query and confirm the plan remains valid against the current graph. If anything changed, refuse to apply and require recomputation.
8. Apply the simulated state change through `graph_client.py` only.
9. Run the actual post-action verification query and show the returned count.
10. Add the LLM intent router/summarizer only after the deterministic flow works. Validate any model-produced intent with Pydantic and limit it to fixed enums. Feed the model only the structured results returned by the backend. Never accept model-supplied paths, costs, IDs, or verification status as facts.
11. If the LLM key is absent, keep all graph functions working and show a labeled deterministic summary derived from live query results.

Exit conditions — all must pass:

- A clean local run displays live data from FalkorDB.
- No graph facts or results are hardcoded in the UI layer.
- Clicking Approve is the only way the demo applies a simulated action.
- The UI reports success only after post-action Cypher returns zero remaining paths.
- An unavailable database, failed centrality query, stale plan, or failed verification produces an explicit error/blocked state.
- The application never claims a real cloud action occurred.
- All Phase 1–3 tests still pass.

---

## 9. LLM contract — limited, grounded, replaceable

The system must remain correct with the LLM disabled.

### Allowed

- Classify a user’s request into a validated enum such as `INVESTIGATE`, `EXPLAIN_LAST_RESULT`, or `HELP`.
- Summarize returned node names, evidence identifiers, centrality scores, candidate costs, action IDs, and the actual verification result.
- Explain why the deterministic engine selected a cut using values supplied by the backend.

### Not allowed

- Generate or modify Cypher.
- Create or infer a node or relationship.
- Change entity costs or mitigation candidates.
- Pick the winning cut independently.
- Approve the human action.
- Write to FalkorDB.
- Claim a result that is absent from the backend result object.

Implement a Pydantic model for the allowed intent enum. Reject invalid model output and show an appropriate error or use the deterministic intent fallback. Keep the UI’s actual action buttons wired to explicit backend service functions rather than letting generated text execute actions.

For summaries, provide the model with a compact JSON object created from actual validated backend results. The UI must render key facts from the structured backend result; model prose is supplementary. Never use the model’s prose as the source of truth.

---

## 10. UI acceptance requirements

Use Streamlit. Keep it to one primary page, with sections or tabs only if needed:

1. **Incident:** source ID, target ID, graph name, query bound, connection status.
2. **Discovered paths:** each real path shown as node sequence, edge mechanism, evidence IDs, and hop count.
3. **Structural analysis:** live centrality table from FalkorDB.
4. **Containment candidates:** candidate IDs/names and costs fetched through Query 4.
5. **Cut plan:** selected nodes, cost, which path(s) each node cuts, and rejected higher-cost alternatives computed by Python.
6. **Approval:** an explicit button showing the exact action set being approved.
7. **Verification:** actual fresh post-action path count and status, with the scope warning.
8. **LLM explanation:** clearly labeled as an explanation of evidence, not an independent finding.

Display a small provenance cue next to graph-derived values, such as “Source: FalkorDB query result.” This cue itself is static UI copy; the values it describes must not be static.

Do not render a generic dashboard with fake charts. If a graph visualization requires too much time, show the real path as a readable node/edge sequence and use FalkorDB Browser for the graph view. A functioning evidence panel is more important than visual effects.

---

## 11. Required tests beyond happy-path assertions

At minimum implement and run these tests:

1. **Seed counts:** 16 nodes, 10 attack edges, 7 dependency edges.
2. **Path discovery:** exactly three paths on pristine seed.
3. **Directionality:** a reversed-only route is not incorrectly returned by the directed attack query.
4. **Hop bound:** the UI and backend state the maximum traversal depth is eight.
5. **Inactive edge:** setting a path edge inactive removes that path from the active result.
6. **Disabled node:** disabled nodes are not treated as active attack route entities.
7. **Live costs:** candidate costs come from FalkorDB, not app constants.
8. **Optimal cut:** live result selects deploy and artifact credential revocations for cost five.
9. **Individual action insufficiency:** either credential alone leaves at least one route.
10. **Controller cut:** release-controller shutdown is recognized as valid and costs ten.
11. **Protected endpoints:** the source and crown jewel cannot be selected as cut candidates.
12. **Determinism:** the same input yields exactly the same action IDs and total cost on repeated calls.
13. **Invalid costs:** negative or invalid costs are rejected.
14. **Candidate cap:** overly large candidate sets fail explicitly rather than running indefinitely.
15. **Pre-action recheck:** a stale or changed graph invalidates the approval plan.
16. **Post-action verification:** after actual graph mutation, a fresh Cypher query returns zero remaining active paths.
17. **Failure mode:** if FalkorDB is down, the application does not show cached success or generated fake data.
18. **LLM disabled:** core graph investigation, cut selection, and verification work without an API key.

Tests may use small in-memory fixtures to test the pure mathematical function. The acceptance path that establishes the cost-five winner must also run against the live seeded FalkorDB graph and feed the actual Phase 2 result into the engine.

---

## 12. README and submission readiness

Create a straightforward `README.md` explaining:

- What CUTLINE does and what it does not do.
- That all attack relationships and operational costs are synthetic demonstration data.
- The exact setup commands for Docker, Python environment, dependencies, seed, tests, and Streamlit.
- The graph schema and relationship semantics.
- The three required graph operations: bounded path discovery, native betweenness centrality, and counterfactual/post-action verification.
- The cut-set algorithm, complexity bound, and exact optimization scope.
- The distinction between structural centrality and action proof.
- How the human approval and simulated mutation work.
- How the optional LLM is constrained and how to run without an API key.
- Known limitations: an eight-hop bound, synthetic topology, no live cloud integrations, and no claim of production security assurance.
- The pinned/tested software versions and exact local run instructions.

Include exact observed test outputs only after running the tests. Never invent benchmark numbers, latency claims, screenshots, or coverage percentages.

---

## 13. Final completion gate

Do not declare the task finished until all of the following are true:

- [ ] The Docker container is running and the Browser UI opens.
- [ ] The seed script populates the actual FalkorDB graph.
- [ ] Query 1 returns the three seeded directed paths.
- [ ] Query 2 runs the actual native centrality procedure and renders returned scores.
- [ ] Query 3 proves the selected cut leaves zero active modeled paths.
- [ ] Costs come from live entity properties.
- [ ] The pure cut-set engine chooses the cost-five token pair over the cost-ten controller shutdown.
- [ ] The UI uses backend results only.
- [ ] Human approval is required before the graph state changes.
- [ ] A new post-action query verifies zero active paths.
- [ ] All automated tests pass in the project's Python environment.
- [ ] A clean-start walkthrough in the README has actually been tested.

When reporting completion, state the exact commands run and the real test outcomes. If a required item is not working, state it as incomplete and do not claim the application is finished.

---

## 14. Official references for API verification

Use these authoritative references when validating the installed version. Prefer the documentation for the exact pinned release when it differs from a moving branch.

- FalkorDB Python client: https://github.com/FalkorDB/falkordb-py
- FalkorDB server and browser quick start: https://github.com/FalkorDB/FalkorDB
- FalkorDB Browser: https://github.com/FalkorDB/falkordb-browser
- FalkorDB algorithm documentation: https://falkordb.github.io/docs-staging/algorithms/betweenness-centrality/
- FalkorDB query/client docs: https://github.com/FalkorDB/falkordb-py
- PostgreSQL recursive CTE documentation (do not make false claims that SQL cannot represent graph traversal): https://www.postgresql.org/docs/17/queries-with.html
- Hackathon official page and rules: https://www.wemakedevs.org/hackathons/falkordb

**Start with Phase 1 now. Do not implement the UI before Phases 1, 2, and 3 pass.**
