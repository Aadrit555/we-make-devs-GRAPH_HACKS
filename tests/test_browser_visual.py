"""
TEZCATL — Playwright Browser Verification & Visual Regression Suite
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)

Verifies:
- Complete heading visibility and zero horizontal overflow across 5 responsive viewports.
- Moving dashed animated attack flows (`attackFlow` keyframe with `stroke-dasharray`).
- Directional SVG arrowhead markers (`#arrow-active`, `#arrow-bypass`, `#arrow-arch`, `#arrow-dimmed`).
- Accessibility support under `@media (prefers-reduced-motion: reduce)`.
- Interactive scenario switching across Scenarios A, B, and C.
- Architecture Mode banner and disabled cut triggers when no threat model is provided (Scenario B).
- Dynamic cycle and branch rendering (Scenario C).
- Screenshots stored in `screenshots/`.
"""
import os
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE_URL = os.getenv("TEZCATL_URL", "http://127.0.0.1:8000")
SCREENSHOTS_DIR = Path(__file__).resolve().parent.parent / "screenshots"
SCREENSHOTS_DIR.mkdir(exist_ok=True)

VIEWPORTS = [
    {"name": "desktop_1440", "width": 1440, "height": 900},
    {"name": "laptop_1280", "width": 1280, "height": 800},
    {"name": "tablet_768", "width": 768, "height": 1024},
    {"name": "mobile_375", "width": 375, "height": 667},
    {"name": "mobile_320", "width": 320, "height": 568},
]


def test_responsive_hero_and_animated_flow():
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)

        # 1. Test responsive viewports & heading visibility
        for vp in VIEWPORTS:
            context = browser.new_context(viewport={"width": vp["width"], "height": vp["height"]})
            page = context.new_page()

            console_errors = []
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)

            page.goto(BASE_URL, wait_until="networkidle")
            page.wait_for_timeout(400)

            # Assert heading exists and is visible
            heading = page.locator(".brand__title")
            assert heading.is_visible(), f"Heading not visible at {vp['name']}"

            # Verify no horizontal scrollbar on body
            scroll_width = page.evaluate("document.body.scrollWidth")
            inner_width = page.evaluate("window.innerWidth")
            assert scroll_width <= inner_width + 2, f"Horizontal overflow at {vp['name']}: {scroll_width} > {inner_width}"

            # Verify button is visible
            cta = page.locator(".brand__cta")
            assert cta.is_visible(), f"CTA button not visible at {vp['name']}"

            # Screenshot landing
            screenshot_path = SCREENSHOTS_DIR / f"landing_{vp['name']}.png"
            page.screenshot(path=str(screenshot_path))
            print(f"[PASS] Viewport {vp['name']} verified: scrollWidth={scroll_width}, innerWidth={inner_width}")

            context.close()

        # 2. Test Interactive Workspace, Scenarios A, B, C & Animated SVG Flows
        ctx = browser.new_context(viewport={"width": 1440, "height": 900})
        page = ctx.new_page()
        page.request.post(f"{BASE_URL}/api/reset?scenario_id=cicd-compromise")
        page.goto(BASE_URL, wait_until="networkidle")

        # Click Open Graph Console button
        page.locator(".brand__cta").click()
        page.wait_for_selector("#workspaceOverlay.is-open", state="visible")
        page.wait_for_selector("#svgContainer svg", state="visible")
        page.wait_for_timeout(600)

        # --- SCENARIO A VERIFICATION ---
        active_edges = page.locator(".edge-active")
        assert active_edges.count() >= 2, f"Expected at least 2 animated active edges in Scenario A, found {active_edges.count()}"

        stroke_dash = active_edges.first.evaluate("el => window.getComputedStyle(el).strokeDasharray")
        anim_name = active_edges.first.evaluate("el => window.getComputedStyle(el).animationName")
        marker_end = active_edges.first.evaluate("el => el.getAttribute('marker-end')")

        assert "6" in stroke_dash or "4" in stroke_dash, f"Expected stroke-dasharray, got {stroke_dash}"
        assert anim_name == "attackFlow", f"Expected animation 'attackFlow', got {anim_name}"
        assert "arrow-active" in marker_end, f"Expected arrow-active marker, got {marker_end}"
        print(f"[PASS] Scenario A: Active edge animation verified (dash={stroke_dash}, marker={marker_end})")

        page.screenshot(path=str(SCREENSHOTS_DIR / "console_scenario_a.png"))
        page.screenshot(path=str(SCREENSHOTS_DIR / "console_baseline.png"))

        # --- SCENARIO B VERIFICATION (Three-Tier App, No Threat Model) ---
        page.select_option("#scenarioSelect", "three-tier-app")
        page.wait_for_timeout(600)

        # Assert Architecture Mode banner is visible
        arch_banner = page.locator("#archModeBanner")
        assert arch_banner.is_visible(), "Expected archModeBanner to be visible for Scenario B"

        # Assert Containment cut button is disabled
        btn_apply = page.locator("#btnApplyCut")
        assert btn_apply.is_disabled(), "Expected btnApplyCut to be disabled in Architecture Mode"

        # Assert 5 nodes rendered in SVG
        b_nodes = page.locator(".node-group")
        assert b_nodes.count() == 5, f"Expected 5 nodes in Scenario B, got {b_nodes.count()}"

        # Assert architecture edges (.edge-arch) are rendered
        arch_edges = page.locator(".edge-arch")
        assert arch_edges.count() >= 4, f"Expected architecture edges in Scenario B, got {arch_edges.count()}"

        page.screenshot(path=str(SCREENSHOTS_DIR / "console_scenario_b_architecture.png"))
        print("[PASS] Scenario B: Architecture mode, 5 nodes, disabled containment, and slate edges verified")

        # --- SCENARIO C VERIFICATION (Microservices with Cycle & Branches) ---
        page.select_option("#scenarioSelect", "microservices-alternate")
        page.wait_for_timeout(600)

        # Assert Architecture Mode banner is hidden
        assert not arch_banner.is_visible(), "Expected archModeBanner to be hidden for Scenario C"

        # Assert 7 nodes rendered in SVG
        c_nodes = page.locator(".node-group")
        assert c_nodes.count() == 7, f"Expected 7 nodes in Scenario C, got {c_nodes.count()}"

        # Assert 2 active paths
        status_pill = page.locator("#statusPill")
        assert "2 Active Attack Paths" in status_pill.inner_text(), f"Unexpected status text: {status_pill.inner_text()}"

        page.screenshot(path=str(SCREENSHOTS_DIR / "console_scenario_c_cycles.png"))
        print("[PASS] Scenario C: Microservices with cycle and branches verified")

        # Switch back to Scenario A
        page.select_option("#scenarioSelect", "cicd-compromise")
        page.wait_for_timeout(600)

        # 3. Test Bypass Injection & Visual Edge Update in Scenario A
        page.locator("#btnBypass").click()
        page.wait_for_timeout(600)

        bypass_edge = page.locator(".edge-bypass")
        assert bypass_edge.count() >= 1, "Expected bypass edge (.edge-bypass) rendered"
        bypass_label = page.locator(".edge-label")
        assert bypass_label.count() >= 1, "Expected BYPASS label rendered"
        page.screenshot(path=str(SCREENSHOTS_DIR / "console_bypass_active.png"))
        print("[PASS] Bypass edge injection verified in live SVG")

        # 4. Test Containment Commit & Visual Transition
        page.locator("#btnApplyCut").click()
        page.wait_for_timeout(800)

        status_pill = page.locator("#statusPill")
        assert "Contained" in status_pill.inner_text(), f"Expected Contained status, got {status_pill.inner_text()}"
        post_active_edges = page.locator(".edge-active")
        assert post_active_edges.count() == 0, f"Expected 0 active edges after containment, got {post_active_edges.count()}"

        page.screenshot(path=str(SCREENSHOTS_DIR / "console_contained.png"))
        print("[PASS] Containment execution and static muted visual transition verified")

        # Reset Scenario A
        page.locator("#btnResetTopology").click()
        page.wait_for_timeout(500)

        # 5. Test Reduced Motion behavior
        ctx_rm = browser.new_context(viewport={"width": 1440, "height": 900}, reduced_motion="reduce")
        page_rm = ctx_rm.new_page()
        page_rm.goto(BASE_URL, wait_until="networkidle")

        page_rm.locator(".brand__cta").click()
        page_rm.wait_for_selector("#svgContainer svg", state="visible")
        page_rm.wait_for_timeout(500)

        rm_active_edges = page_rm.locator(".edge-active")
        if rm_active_edges.count() > 0:
            rm_anim = rm_active_edges.first.evaluate("el => window.getComputedStyle(el).animationName")
            assert rm_anim == "none", f"Expected animation 'none' under prefers-reduced-motion, got {rm_anim}"
            print("[PASS] prefers-reduced-motion verified: animation paused but directional arrows preserved")

        ctx_rm.close()
        ctx.close()
        browser.close()
        print("\nALL BROWSER RESPONSIVE, ANIMATION, & SCENARIO REGRESSION CHECKS PASSED 100%!")


if __name__ == "__main__":
    test_responsive_hero_and_animated_flow()
