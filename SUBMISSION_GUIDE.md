# WeMakeDevs & FalkorDB Graph Hacks Submission Guide

**Project Name:** TEZCATL — Graph-Native Incident Containment Engine  
**Track:** Track 01: Agents That Act on Connected Data  
**Repository:** [https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS](https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)  
**Author:** Aadrit555 ([https://github.com/Aadrit555](https://github.com/Aadrit555))  
**Submission Portal:** [https://www.wemakedevs.org/hackathons/falkordb/submit](https://www.wemakedevs.org/hackathons/falkordb/submit)

---

## 1. Portal Submission Field Answers

### Field: Project Title
```text
TEZCATL // Graph-Native Breach Containment Engine on FalkorDB
```

### Field: Track
```text
Track 01: Agents That Act on Connected Data
```

### Field: Short Description / Tagline (Under 200 characters)
```text
Isolates multi-hop security breaches using FalkorDB variable-length traversals, native algo.betweenness, reverse-dependency blast radius analysis, and shadow-graph sandbox verification.
```

### Field: GitHub Repository URL
```text
https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS
```

### Field: What does your project do and what problem does it solve?
```text
When a CI/CD build runner or developer workload is compromised, attackers move laterally across temporary credentials, IAM roles, and package repositories to reach high-value crown-jewel assets like production signing keys. 

Traditional relational SQL cannot efficiently traverse variable-length lateral movement without deep recursive queries that break at scale. Vector databases fail completely because semantic similarity embeddings cannot model directional permissions or prove reachability. When responders lack graph visibility, they apply blunt sledgehammer fixes—such as shutting down the central release controller—which knocks critical downstream revenue services offline.

TEZCATL acts directly on connected data inside FalkorDB:
1. Traverses all active directed breach paths (*1..8 hops) from compromised workloads in sub-10ms latency.
2. Executes FalkorDB native algo.betweenness centrality to locate structural choke points.
3. Performs dynamic reverse multi-hop dependency traversals ((:Service)-[:DEPENDS_ON*1..4]->(:Entity)) to calculate the true dollar/revenue disruption cost of severing each node.
4. Solves a combinatorial minimum-cost vertex cut to find the mathematically minimal disruption action (saving $9 revenue impact over shutting down the controller).
5. Clones prod_graph to an isolated memory graph (tezcatl_mirror) to simulate and verify that reachability drops to 0 before committing the change.
6. Generates a tamper-evident SHA-256 audit receipt of pre- and post-mitigation graph state.
```

### Field: How does your project use FalkorDB? (How did FalkorDB enable your solution?)
```text
FalkorDB is the foundational compute and memory engine for the entire product:
- Graph Traversal: Variable-length directed path discovery (:ATTACK_STEP*1..8) executes directly on FalkorDB's linear-algebraic graph engine.
- Graph Algorithms: Native FalkorDB algo.betweenness procedure ranks structural bridge nodes without exporting graph data to external Python memory.
- Multi-Graph Isolation: FalkorDB's multi-graph architecture enables live cloning from prod_graph to tezcatl_mirror. The agent mutates the shadow graph, verifies 0 remaining paths in memory, and proves containment safety before touching production.
- Reverse Traversal: Dynamic service blast radius calculation traverses reverse DEPENDS_ON edges to sum downstream business impact.
- 100% Parameterized Cypher: Zero f-strings or string interpolation are used across all queries.

If FalkorDB is removed, the engine cannot run. Zero simulation, zero mock fallbacks, and zero external LLM APIs are used.
```

### Field: Technologies & Libraries Used
```text
FalkorDB, Python 3.11+, FastAPI, Pydantic v2, Docker Compose, Pytest, Vanilla CSS/HTML (no external heavy frameworks, zero external LLM API dependencies).
```

### Field: AI Tooling / Acknowledgement Disclosure
```text
Google Antigravity coding assistant was used as an interactive pair programming tool during development for codebase refactoring, drafting integration test matrices, running Docker CLI tasks, and documentation formatting. All core graph architecture, Cypher queries, and mathematical solver algorithms were designed and authored by Aadrit555. Zero proprietary LLMs or external agent frameworks are used at runtime.
```

---

## 2. 90-Second Demo Video Walkthrough Script

Use this exact structure to record the 90-second submission video:

### [00:00 - 00:15] Hook & Problem Statement
- **Visual:** Open landing page at `http://localhost:8000` showing the clean paper/meadow layout and giant frosted "TEZCATL" wordmark.
- **Voiceover:** *"Hi, I'm Aadrit555, and this is TEZCATL—a graph-native incident containment agent built on FalkorDB for Track 01. When a CI build runner is compromised, attackers hop across tokens, roles, and registries to steal production signing keys. Relational SQL and vector RAG fail at lateral movement, causing responders to shut down core release controllers and break production services."*

### [00:15 - 00:35] Live Attack Path Discovery & FalkorDB Centrality
- **Visual:** Click **"Launch TEZCATL Console"** to open the interactive sheet.
- **Voiceover:** *"Clicking 'Launch Console' connects live to FalkorDB on port 6379. In Tab 01, FalkorDB executes a variable-length Cypher query up to 8 hops, discovering two distinct routes to our crown jewel in under 10 milliseconds. In Tab 02, FalkorDB executes its native algo.betweenness algorithm, highlighting release-controller as the structural choke point with a centrality score of 1.0."*

### [00:35 - 00:55] Reverse Dependency Blast Radius & Vertex-Cut Optimization
- **Visual:** Point to the Candidate Disruption table showing costs: `release-controller` (Cost: 14) vs `tok-deploy-alpha` + `tok-artifact-rw` (Cost: 5).
- **Voiceover:** *"Instead of shutting down the controller—which would take down our Global Checkout API and cost $14—TEZCATL executes a reverse multi-hop traversal over DEPENDS_ON relationships. Our deterministic vertex-cut solver discovers that revoking both the deploy token and artifact token severs 100% of attack paths for an operational cost of only 5, saving 9 units of revenue impact."*

### [00:55 - 01:15] Shadow-Graph Sandbox Verification & Dynamic Mutation
- **Visual:** Switch to Tab 03 (`Shadow Graph (tezcatl_mirror)`) and show the verified 0 paths remaining.
- **Visual:** Click **"Bypass Stress-Test"** in the top action bar to inject a lateral SSH socket (`EV-999`).
- **Voiceover:** *"Before anything touches production, TEZCATL clones prod_graph into an isolated sandbox called tezcatl_mirror, severs the tokens, and mathematically verifies remaining paths drop to zero. When we stress-test the engine with a direct bypass route, the graph updates instantly and the solver dynamically shifts the optimal cut to release-controller. Clicking again tears it down."*

### [01:15 - 01:30] Gated Containment Commit & Conclusion
- **Visual:** Click **"Execute Verified Containment"**. Show the active paths drop to 0, graph status change to `CONTAINED_AND_VERIFIED`, and display the SHA-256 audit receipt.
- **Voiceover:** *"With one click, authorized containment commits to prod_graph, dropping reachability to 0 and generating a cryptographic SHA-256 audit receipt. TEZCATL runs with 100% first-party code, zero external APIs, zero hallucinations, and 50 out of 50 passing tests. Thank you!"*

