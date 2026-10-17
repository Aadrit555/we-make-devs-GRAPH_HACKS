"""
TEZCATL — Multi-Scenario Registry & Manifest Management
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)

Manages isolated security scenarios, validation, and graph binding.
Ensures prod_graph is never overwritten by test or imported scenarios.
"""
from typing import Dict, Any, List, Optional
import re
from backend.models import (
    SecurityTopologyManifest,
    ProjectInfo,
    ManifestNode,
    ManifestEdge,
    SecurityScenario,
    EligibleMitigation,
    ScenarioSummary,
)
from backend.config import PROD_GRAPH, MIRROR_GRAPH


# ==============================================================================
# SCENARIO A: CI/CD PIPELINE COMPROMISE (Canonical Demo)
# ==============================================================================

SCENARIO_A_MANIFEST = SecurityTopologyManifest(
    schema_version=1,
    project=ProjectInfo(id="cicd-compromise", name="Scenario A: CI/CD Pipeline Compromise"),
    nodes=[
        ManifestNode(id="ci-runner-07", name="CI Build Runner 07", kind="workload", criticality="standard", status="active"),
        ManifestNode(id="staging-worker-02", name="Staging Worker 02", kind="workload", criticality="standard", status="active"),
        ManifestNode(id="tok-deploy-alpha", name="CI Deploy Token Alpha", kind="credential", criticality="high", status="active"),
        ManifestNode(id="tok-artifact-rw", name="Artifact Registry RW Token", kind="credential", criticality="high", status="active"),
        ManifestNode(id="role-cloud-deployer", name="IAM Cloud Deployer Role", kind="role", criticality="high", status="active"),
        ManifestNode(id="pkg-registry-core", name="Internal Package Registry", kind="workload", criticality="high", status="active"),
        ManifestNode(id="release-controller", name="Prod Release Controller", kind="workload", criticality="bottleneck", status="active"),
        ManifestNode(id="prod-signing-key", name="Root Production Signing Key", kind="secret", criticality="crown_jewel", status="active"),
    ],
    edges=[
        ManifestEdge(id="e-a-01", source="ci-runner-07", target="tok-deploy-alpha", type="ATTACK_STEP", metadata={"mechanism": "ENV_MEM_DUMP", "evidence_id": "EV-101"}),
        ManifestEdge(id="e-a-02", source="tok-deploy-alpha", target="role-cloud-deployer", type="ATTACK_STEP", metadata={"mechanism": "STS_ASSUME_ROLE", "evidence_id": "EV-102"}),
        ManifestEdge(id="e-a-03", source="role-cloud-deployer", target="release-controller", type="ATTACK_STEP", metadata={"mechanism": "K8S_EXEC_PRIV", "evidence_id": "EV-103"}),
        ManifestEdge(id="e-a-04", source="ci-runner-07", target="tok-artifact-rw", type="ATTACK_STEP", metadata={"mechanism": "CACHE_POISON_TOKEN", "evidence_id": "EV-104"}),
        ManifestEdge(id="e-a-05", source="tok-artifact-rw", target="pkg-registry-core", type="ATTACK_STEP", metadata={"mechanism": "MALICIOUS_WHEEL_PUSH", "evidence_id": "EV-105"}),
        ManifestEdge(id="e-a-06", source="pkg-registry-core", target="release-controller", type="ATTACK_STEP", metadata={"mechanism": "AUTO_BUILD_TRIGGER", "evidence_id": "EV-106"}),
        ManifestEdge(id="e-a-07", source="staging-worker-02", target="tok-artifact-rw", type="ATTACK_STEP", metadata={"mechanism": "SHARED_MOUNT_LEAK", "evidence_id": "EV-107"}),
        ManifestEdge(id="e-a-08", source="release-controller", target="prod-signing-key", type="ATTACK_STEP", metadata={"mechanism": "KMS_DECRYPT_GRANT", "evidence_id": "EV-108"}),
    ],
    scenario=SecurityScenario(
        source_id="ci-runner-07",
        target_ids=["prod-signing-key"],
        allowed_traversal_types=["ATTACK_STEP"],
        max_depth=8,
        eligible_mitigations=[
            EligibleMitigation(node_id="tok-deploy-alpha", blast_cost=2, impact_justification="CI telemetry pipeline degradation", impacted_services=["svc-ci-telemetry"]),
            EligibleMitigation(node_id="tok-artifact-rw", blast_cost=3, impact_justification="Artifact mirror sync delay", impacted_services=["svc-artifact-sync"]),
            EligibleMitigation(node_id="release-controller", blast_cost=14, impact_justification="Checkout API & zero-downtime release train blocked", impacted_services=["svc-checkout-api", "svc-release-pipe", "svc-auth-gateway"]),
        ],
        protected_nodes=["prod-signing-key"],
        description="Canonical WeMakeDevs baseline demonstration on prod_graph."
    )
)


# ==============================================================================
# SCENARIO B: THREE-TIER WEB APP (Architecture Only, No Threat Model)
# ==============================================================================

SCENARIO_B_MANIFEST = SecurityTopologyManifest(
    schema_version=1,
    project=ProjectInfo(id="three-tier-app", name="Scenario B: Three-Tier Web Architecture"),
    nodes=[
        ManifestNode(id="frontend-web", name="Frontend Web App", kind="application", criticality="medium", status="active"),
        ManifestNode(id="api-gateway", name="API Gateway", kind="service", criticality="high", status="active"),
        ManifestNode(id="order-worker", name="Order Background Worker", kind="service", criticality="high", status="active"),
        ManifestNode(id="redis-cache", name="Redis Session Cache", kind="service", criticality="medium", status="active"),
        ManifestNode(id="postgres-primary", name="PostgreSQL Primary DB", kind="database", criticality="crown_jewel", status="active"),
    ],
    edges=[
        ManifestEdge(id="e-b-01", source="frontend-web", target="api-gateway", type="CALLS", metadata={"mechanism": "REST_HTTPS", "evidence_id": "ARCH-B01"}),
        ManifestEdge(id="e-b-02", source="api-gateway", target="redis-cache", type="READS_FROM", metadata={"mechanism": "REDIS_TCP", "evidence_id": "ARCH-B02"}),
        ManifestEdge(id="e-b-03", source="api-gateway", target="order-worker", type="CALLS", metadata={"mechanism": "RABBITMQ_AMQP", "evidence_id": "ARCH-B03"}),
        ManifestEdge(id="e-b-04", source="order-worker", target="postgres-primary", type="WRITES_TO", metadata={"mechanism": "PG_TCP_POOL", "evidence_id": "ARCH-B04"}),
        ManifestEdge(id="e-b-05", source="redis-cache", target="postgres-primary", type="DEPENDS_ON", metadata={"mechanism": "STATE_PERSISTENCE", "evidence_id": "ARCH-B05"}),
    ],
    scenario=None  # No threat model supplied. 0 ATTACK_STEP relationships.
)


# ==============================================================================
# SCENARIO C: MICROSERVICES FLEET (Cycles, Branches, and Shared Bottleneck)
# ==============================================================================

SCENARIO_C_MANIFEST = SecurityTopologyManifest(
    schema_version=1,
    project=ProjectInfo(id="microservices-alternate", name="Scenario C: Microservices Branching & Cycle Topology"),
    nodes=[
        ManifestNode(id="edge-ingress", name="Edge API Ingress", kind="gateway", criticality="critical", status="active"),
        ManifestNode(id="order-processor", name="Order Processor", kind="service", criticality="high", status="active"),
        ManifestNode(id="fraud-checker", name="Fraud Verification Service", kind="service", criticality="medium", status="active"),
        ManifestNode(id="telemetry-aggregator", name="Telemetry Aggregator", kind="service", criticality="low", status="active"),
        ManifestNode(id="auth-broker", name="Internal Auth Broker", kind="service", criticality="high", status="active"),
        ManifestNode(id="vault-secrets", name="HashiCorp Secrets Vault", kind="database", criticality="crown_jewel", status="active"),
        ManifestNode(id="billing-service", name="Billing Engine", kind="service", criticality="medium", status="active"),
    ],
    edges=[
        # Primary branch 1: edge-ingress -> order-processor -> fraud-checker -> auth-broker
        ManifestEdge(id="e-c-01", source="edge-ingress", target="order-processor", type="ATTACK_STEP", metadata={"mechanism": "PAYLOAD_EXPLOIT", "evidence_id": "EV-C101"}),
        ManifestEdge(id="e-c-02", source="order-processor", target="fraud-checker", type="ATTACK_STEP", metadata={"mechanism": "RPC_HIJACK", "evidence_id": "EV-C102"}),
        # Directed cycle back from fraud-checker to order-processor (architecture feedback loop)
        ManifestEdge(id="e-c-03", source="fraud-checker", target="order-processor", type="CALLS", metadata={"mechanism": "ASYNC_CALLBACK", "evidence_id": "EV-C103"}),
        ManifestEdge(id="e-c-04", source="fraud-checker", target="auth-broker", type="ATTACK_STEP", metadata={"mechanism": "MTLS_IMPERSONATION", "evidence_id": "EV-C104"}),
        # Parallel branch 2: edge-ingress -> telemetry-aggregator -> auth-broker
        ManifestEdge(id="e-c-05", source="edge-ingress", target="telemetry-aggregator", type="ATTACK_STEP", metadata={"mechanism": "LOG_INJECTION", "evidence_id": "EV-C105"}),
        ManifestEdge(id="e-c-06", source="telemetry-aggregator", target="auth-broker", type="ATTACK_STEP", metadata={"mechanism": "CREDENTIAL_LEAK", "evidence_id": "EV-C106"}),
        # Convergent bottleneck to crown jewel
        ManifestEdge(id="e-c-07", source="auth-broker", target="vault-secrets", type="ATTACK_STEP", metadata={"mechanism": "TOKEN_EXCHANGE", "evidence_id": "EV-C107"}),
        # Architecture dependency from auth-broker to billing-service
        ManifestEdge(id="e-c-08", source="auth-broker", target="billing-service", type="DEPENDS_ON", metadata={"mechanism": "SERVICE_DEPENDENCY", "evidence_id": "EV-C108"}),
    ],
    scenario=SecurityScenario(
        source_id="edge-ingress",
        target_ids=["vault-secrets"],
        allowed_traversal_types=["ATTACK_STEP"],
        max_depth=8,
        eligible_mitigations=[
            EligibleMitigation(node_id="telemetry-aggregator", blast_cost=2, impact_justification="Temporary loss of application metrics", impacted_services=["telemetry-pipeline"]),
            EligibleMitigation(node_id="fraud-checker", blast_cost=6, impact_justification="Fraud checks queued for manual review", impacted_services=["fraud-shield"]),
            EligibleMitigation(node_id="auth-broker", blast_cost=9, impact_justification="Central auth gateway disruption affecting billing", impacted_services=["billing-service", "vault-secrets"]),
            EligibleMitigation(node_id="order-processor", blast_cost=14, impact_justification="Primary order processing pipeline halted", impacted_services=["order-pipeline"]),
        ],
        protected_nodes=["vault-secrets"],
        description="Branching attack paths with an architectural cycle, shared bottleneck at auth-broker, and independent blast costs."
    )
)


class ScenarioRegistry:
    """Maintains active security scenarios and their isolated FalkorDB graph bindings."""

    def __init__(self):
        self._scenarios: Dict[str, Dict[str, Any]] = {}
        self._register_defaults()

    def _register_defaults(self):
        # Scenario A: CI/CD Pipeline (Canonical Demo)
        self._scenarios["cicd-compromise"] = {
            "id": "cicd-compromise",
            "name": "Scenario A: CI/CD Pipeline Compromise",
            "description": "Canonical baseline demo: compromised CI runner, deploy tokens, release controller bottleneck, crown jewel signing key.",
            "graph_name": PROD_GRAPH,
            "mirror_name": MIRROR_GRAPH,
            "manifest": SCENARIO_A_MANIFEST,
            "is_default": True,
        }

        # Scenario B: Three-Tier Web App (Architecture Only)
        self._scenarios["three-tier-app"] = {
            "id": "three-tier-app",
            "name": "Scenario B: Three-Tier Web Architecture",
            "description": "Frontend, API Gateway, Order Worker, Redis Cache, Postgres DB. Pure architecture topology without an explicit attack model.",
            "graph_name": "scen_three_tier_prod",
            "mirror_name": "scen_three_tier_mirror",
            "manifest": SCENARIO_B_MANIFEST,
            "is_default": False,
        }

        # Scenario C: Microservices Branching & Cycle Topology
        self._scenarios["microservices-alternate"] = {
            "id": "microservices-alternate",
            "name": "Scenario C: Microservices Branching & Cycle Topology",
            "description": "Compromised edge ingress with cycle between order-processor & fraud-checker, telemetry bypass, auth-broker bottleneck, vault-secrets crown jewel.",
            "graph_name": "scen_microservices_prod",
            "mirror_name": "scen_microservices_mirror",
            "manifest": SCENARIO_C_MANIFEST,
            "is_default": False,
        }

    def get_scenario(self, scenario_id: str) -> Optional[Dict[str, Any]]:
        return self._scenarios.get(scenario_id)

    def list_scenarios(self) -> List[ScenarioSummary]:
        summaries = []
        for s in self._scenarios.values():
            m = s["manifest"]
            sc = m.scenario
            summaries.append(
                ScenarioSummary(
                    id=s["id"],
                    name=s["name"],
                    description=s["description"],
                    graph_name=s["graph_name"],
                    mirror_name=s["mirror_name"],
                    source_id=sc.source_id if sc else (m.nodes[0].id if m.nodes else "unknown"),
                    target_ids=sc.target_ids if sc else [],
                    has_threat_model=sc is not None,
                    threat_model_message=None if sc is not None else "Architecture topology loaded. Security analysis requires an explicit threat model.",
                    node_count=len(m.nodes),
                    edge_count=len(m.edges),
                )
            )
        return summaries

    def register_imported_scenario(self, manifest: SecurityTopologyManifest) -> Dict[str, Any]:
        """Registers a newly imported validated manifest into an isolated graph pair."""
        slug = re.sub(r"[^a-zA-Z0-9_]", "_", manifest.project.id.lower())
        graph_name = f"scen_{slug}_prod"
        mirror_name = f"scen_{slug}_mirror"

        # Refuse to overwrite prod_graph with imported scenario
        if graph_name in (PROD_GRAPH, MIRROR_GRAPH):
            graph_name = f"scen_custom_{slug}_prod"
            mirror_name = f"scen_custom_{slug}_mirror"

        entry = {
            "id": manifest.project.id,
            "name": manifest.project.name,
            "description": manifest.scenario.description if manifest.scenario else "Custom imported topology.",
            "graph_name": graph_name,
            "mirror_name": mirror_name,
            "manifest": manifest,
            "is_default": False,
        }
        self._scenarios[manifest.project.id] = entry
        return entry


# Global singleton scenario registry
SCENARIO_REGISTRY = ScenarioRegistry()
