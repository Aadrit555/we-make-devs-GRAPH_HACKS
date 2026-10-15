"""
app.py — Streamlit UI console for CUTLINE v2.

Adheres strictly to BUILD_INSTRUCTIONS.md:
- Incident Overview (source ci_runner, target signing_key)
- Attack-Path Evidence (live paths from FalkorDB with mechanisms and evidence IDs)
- Structural Analysis (live FalkorDB betweenness centrality table)
- Containment Candidates & Cost Comparison (cost 5 plan vs cost 10 controller shutdown)
- Explicit Human Approval Button
- Fresh Post-Action Zero-Path Verification Query
- Optional Grounded LLM Explanation
"""

import streamlit as st
import pandas as pd
from typing import Optional, List, Dict, Any

from logic import ContainmentService, GraphFreshnessError
from graph_client import FalkorGraphClient
from llm_router import LLMRoutingLayer, AgentIntent

st.set_page_config(
    page_title="CUTLINE v2 — Graph-Native Incident Containment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize service in session state
if "service" not in st.session_state:
    st.session_state.service = ContainmentService()

if "llm_router" not in st.session_state:
    st.session_state.llm_router = LLMRoutingLayer()

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None

if "containment_status" not in st.session_state:
    st.session_state.containment_status = "IDLE"  # IDLE, ANALYZED, APPLIED, VERIFIED, ERROR

if "post_verification_count" not in st.session_state:
    st.session_state.post_verification_count = None

if "last_error" not in st.session_state:
    st.session_state.last_error = None


# ==============================================================================
# Header & Incident Scope Banner
# ==============================================================================

st.title("🛡️ CUTLINE v2 — Graph-Native Attack Path Containment")
st.caption(
    "Automated incident investigation, deterministic minimum-cost vertex-cut calculation, "
    "and closed-loop verification over FalkorDB connected data."
)

st.markdown(
    """> ⚠️ **Synthetic Demonstration Scope Warning:**
> All attack relationships, infrastructure entities, and operational impact scores are modeled demonstration artifacts.
> Path discovery and counterfactual containment calculations are strictly bounded to 8 directed hops over `cutline_demo`.
> No production cloud or live AWS remediation actions are performed."""
)

st.divider()

# ==============================================================================
# Sidebar: Target Configuration & System Health
# ==============================================================================

with st.sidebar:
    st.header("⚙️ Incident Target Config")
    source_id = st.text_input("Incident Source ID", value="ci_runner")
    target_id = st.text_input("Crown Jewel Target ID", value="signing_key")
    max_hops = st.number_input("Max Traversal Hops", min_value=1, max_value=8, value=8)

    st.markdown("---")
    st.header("🔌 Database & Engine Status")
    is_connected = st.session_state.service.client.check_connection()
    if is_connected:
        st.success("FalkorDB Connected (127.0.0.1:6379)")
    else:
        st.error("FalkorDB Unavailable")

    llm_status = "Configured" if st.session_state.llm_router.is_available else "Deterministic Fallback"
    st.info(f"LLM Routing Layer: {llm_status}")

    st.markdown("---")
    if st.button("🔄 Reset Demo Seed Graph", use_container_width=True):
        import seed
        try:
            seed.seed_database()
            st.session_state.analysis_result = None
            st.session_state.containment_status = "IDLE"
            st.session_state.post_verification_count = None
            st.session_state.last_error = None
            st.success("Graph reset to pristine initial state.")
            st.rerun()
        except Exception as e:
            st.error(f"Failed to reset graph: {e}")


# ==============================================================================
# Incident Overview Metrics
# ==============================================================================

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Compromised Asset", source_id, help="Starting node of active incident")
with col2:
    st.metric("Crown Jewel Target", target_id, help="Target asset requiring protection")
with col3:
    st.metric("Graph Scope", f"≤ {max_hops} Hops", help="Search depth bound")
with col4:
    status_label = {
        "IDLE": "Ready for Scan",
        "ANALYZED": "Plan Proposed",
        "APPLIED": "Action Executed",
        "VERIFIED": "Containment Verified",
        "ERROR": "Investigation Error"
    }.get(st.session_state.containment_status, "Unknown")
    st.metric("Containment Status", status_label)

st.markdown("")

# ==============================================================================
# Natural Language / Agent Prompt Interface
# ==============================================================================

with st.expander("💬 Natural Language Agent Dispatcher", expanded=False):
    user_prompt = st.text_input("Ask the agent (e.g. 'Investigate the compromised runner', 'Explain the plan'):")
    if user_prompt:
        routing = st.session_state.llm_router.route_user_query(user_prompt)
        st.caption(f"**Intent Classified:** `{routing.intent.value}` (Confidence: {routing.confidence:.2f}) — {routing.reasoning}")

# ==============================================================================
# Action Control: Run Investigation
# ==============================================================================

action_col1, action_col2 = st.columns([1, 4])
with action_col1:
    if st.button("🔍 Investigate & Plan", type="primary", use_container_width=True):
        if not is_connected:
            st.error("Cannot investigate: FalkorDB is unavailable. Please start the container.")
        else:
            try:
                with st.spinner("Executing bounded multi-hop discovery and cut calculation..."):
                    res = st.session_state.service.analyze_incident(
                        source_id=source_id,
                        target_id=target_id,
                        max_hops=max_hops
                    )
                    st.session_state.analysis_result = res
                    st.session_state.containment_status = "ANALYZED"
                    st.session_state.last_error = None
                    st.rerun()
            except Exception as e:
                st.session_state.last_error = str(e)
                st.session_state.containment_status = "ERROR"
                st.error(f"Investigation failed: {e}")

# ==============================================================================
# Evidence & Planning Results Dashboard
# ==============================================================================

res = st.session_state.analysis_result

if res is not None:
    tab_paths, tab_centrality, tab_comparison, tab_approval = st.tabs([
        "📍 Discovered Attack Paths",
        "📊 Betweenness Centrality",
        "⚖️ Containment Cost Comparison",
        "✅ Approval & Live Verification"
    ])

    # --------------------------------------------------------------------------
    # Tab 1: Discovered Attack Paths
    # --------------------------------------------------------------------------
    with tab_paths:
        st.subheader("Discovered Multi-Hop Attack Paths")
        st.caption(f"Source: FalkorDB Query 1 (Traversing active ATTACK_STEP relationships, ≤ {max_hops} hops)")

        if not res.discovered_paths:
            st.success("No active directed attack paths detected. The crown jewel is safe.")
        else:
            st.write(f"Found **{len(res.discovered_paths)}** active directed attack paths:")
            for idx, p in enumerate(res.discovered_paths, start=1):
                with st.container(border=True):
                    st.markdown(f"**Path {idx}** ({p.hops} hops): `{' ➔ '.join(p.node_ids)}`")
                    st.markdown(f"*Entities:* {', '.join(p.node_names)}")
                    # Show mechanisms and evidence
                    step_details = []
                    for i in range(len(p.mechanisms)):
                        src_name = p.node_names[i]
                        dst_name = p.node_names[i+1]
                        mech = p.mechanisms[i]
                        ev = p.evidence_ids[i]
                        step_details.append(f"- **{src_name} ➔ {dst_name}:** {mech} *(Evidence ID: `{ev}`)*")
                    st.markdown("\n".join(step_details))

    # --------------------------------------------------------------------------
    # Tab 2: Betweenness Centrality
    # --------------------------------------------------------------------------
    with tab_centrality:
        st.subheader("Native Graph Centrality Analysis")
        st.caption("Source: FalkorDB Query 2 (`CALL algo.betweenness(...)` over ATTACK_STEP relationships)")
        st.info(
            "📌 **Engineering Note:** Betweenness centrality identifies structural bridge entities in the graph, "
            "but centrality does NOT prove containment. Minimum-cost containment requires intersecting all active routes."
        )
        if res.centrality_scores:
            df_centrality = pd.DataFrame([
                {"Entity ID": c.id, "Display Name": c.name, "Entity Kind": c.kind, "Betweenness Score": c.score}
                for c in res.centrality_scores
            ])
            st.dataframe(df_centrality, use_container_width=True, hide_index=True)

    # --------------------------------------------------------------------------
    # Tab 3: Containment Comparison
    # --------------------------------------------------------------------------
    with tab_comparison:
        st.subheader("Candidate Mitigations & Combinatorial Cost Comparison")
        st.caption("Source: FalkorDB Query 4 candidate properties & cut_set_calculator.py")

        c1, c2 = st.columns([1, 1])

        with c1:
            st.markdown("#### Eligible Mitigation Candidates")
            df_cands = pd.DataFrame([
                {"Candidate ID": c.id, "Name": c.name, "Kind": c.kind, "Criticality": c.criticality, "Impact Cost": c.cost}
                for c in res.eligible_candidates
            ])
            st.dataframe(df_cands, use_container_width=True, hide_index=True)

        with c2:
            st.markdown("#### Containment Plan Trade-Off")
            plan = res.recommended_plan
            if plan:
                st.success(f"**Recommended Plan (Cost {plan.total_cost}):**")
                st.markdown(f"- **Actions Selected:** `{', '.join(plan.selected_node_ids)}`")
                st.markdown(f"- **Total Disruption Impact:** `{plan.total_cost}`")
                st.markdown(f"- **Paths Severed:** `{plan.paths_covered_count} of {plan.paths_evaluated_count}`")
                for cid, paths_hit in plan.path_intersections.items():
                    st.markdown(f"  * `{cid}` disconnects Path(s): `{[p+1 for p in paths_hit]}`")

                st.markdown("---")
                st.warning("**Rejected Alternative (Cost 10):**")
                st.markdown("- **Action:** Disable `release_controller` alone.")
                st.markdown("- **Impact:** Cost 10 (2x more disruptive than revoking both credentials).")

        # Grounded LLM Explanation Box
        st.markdown("#### 🤖 Grounded Explanation")
        summary_context = {
            "selected_nodes": plan.selected_node_ids if plan else [],
            "total_cost": plan.total_cost if plan else 0,
            "paths_count": len(res.discovered_paths),
            "alt_controller_cost": 10
        }
        explanation_text = st.session_state.llm_router.summarize_plan_evidence(summary_context)
        st.markdown(f"> {explanation_text}")

    # --------------------------------------------------------------------------
    # Tab 4: Human Approval & Live Verification
    # --------------------------------------------------------------------------
    with tab_approval:
        st.subheader("Human Authorization & Simulated Closed-Loop Verification")
        st.caption("Pre-Action Revalidation ➔ FalkorDB Mutation (Query 5) ➔ Post-Action Verification (Query 3)")

        plan = res.recommended_plan

        if plan is None or len(plan.selected_node_ids) == 0:
            st.info("No containment actions required.")
        elif st.session_state.containment_status == "VERIFIED":
            st.success("🎉 **CONTAINMENT VERIFIED:** Zero active attack paths remain to the crown jewel.")
            st.metric("Post-Action Remaining Attack Paths", st.session_state.post_verification_count)
            st.caption("Fresh post-action verification query confirmed 0 active paths within the 8-hop bound.")
        else:
            st.warning(
                f"⚠️ **Human Approval Required:** Approving this action will simulate containment by disabling "
                f"`{', '.join(plan.selected_node_ids)}` and setting their incident attack relationships inactive in FalkorDB."
            )

            # Prevent double-click or accidental mutations
            approve_clicked = st.button(
                f"🚨 Approve and Apply Containment Plan ({', '.join(plan.selected_node_ids)})",
                type="primary",
                use_container_width=True
            )

            if approve_clicked:
                try:
                    with st.spinner("Revalidating graph freshness and applying simulated containment..."):
                        # 1. Freshness recheck & Apply
                        mutation_res = st.session_state.service.validate_and_apply_plan(
                            source_id=source_id,
                            target_id=target_id,
                            expected_cut_ids=plan.selected_node_ids,
                            max_hops=max_hops
                        )

                        # 2. Fresh post-action verification query
                        post_count = st.session_state.service.verify_containment_post_action(
                            source_id=source_id,
                            max_hops=max_hops
                        )

                        st.session_state.post_verification_count = post_count

                        if post_count == 0:
                            st.session_state.containment_status = "VERIFIED"
                            st.success(
                                f"Containment successfully applied ({mutation_res.updated_node_count} nodes disabled, "
                                f"{mutation_res.updated_edge_count} relationships deactivated). "
                                f"Post-action verification query confirms ZERO remaining paths!"
                            )
                            st.rerun()
                        else:
                            st.session_state.containment_status = "ERROR"
                            st.error(
                                f"VERIFICATION FAILED: Expected 0 remaining paths, but post-action query returned {post_count} paths!"
                            )
                except GraphFreshnessError as gfe:
                    st.error(f"Execution rejected: {gfe}")
                except Exception as exc:
                    st.error(f"Unexpected error applying containment: {exc}")

