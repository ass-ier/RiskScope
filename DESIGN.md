---
name: RiskScope analyst workbench
description: A restrained, evidence-led local risk investigation interface.
colors:
  primary: "#2457c7"
  primary-hover: "#1e429b"
  ink: "#17263c"
  body: "#26354a"
  muted: "#596b82"
  canvas: "#f8fafc"
  surface: "#ffffff"
  chrome: "#f0f4f9"
  line: "#dde5ef"
  focus: "#4b7df0"
  critical-text: "#9d3645"
  critical-surface: "#fceef0"
  high-text: "#925617"
  high-surface: "#fff3e8"
  medium-text: "#78631b"
  medium-surface: "#f8f4e8"
  success-text: "#32654f"
  success-surface: "#eaf5ef"
  chart-grid: "#e2e8f0"
  chart-axis: "#526176"
  chart-open: "#2563eb"
  chart-remediated: "#16856d"
  chart-new: "#718096"
  chart-overdue: "#b45309"
  graph-node: "#e7eef9"
  graph-node-border: "#5874a2"
  graph-label: "#25344e"
  graph-vulnerability: "#fff1e7"
  graph-vulnerability-border: "#b77940"
  graph-internet: "#dbeafe"
  graph-service: "#edf5f1"
  graph-service-border: "#528574"
  graph-edge: "#a1aec0"
  graph-selected: "#1d4ed8"
typography:
  body:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.65
  headline:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: "1.9rem"
    fontWeight: 650
    lineHeight: 1.3
    letterSpacing: "-0.03em"
  title:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: "1.1rem"
    fontWeight: 650
    lineHeight: 1.3
  label:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: "0.85rem"
    fontWeight: 500
    lineHeight: 1.5
rounded:
  control: "4px"
  button: "5px"
  surface: "6px"
spacing:
  compact: "8px"
  control: "13px"
  surface: "20px"
  section: "22px"
  workspace: "30px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.surface}"
    rounded: "{rounded.button}"
    padding: "8px 13px"
    height: "38px"
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
    textColor: "{colors.surface}"
  work-surface:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.surface}"
    padding: "20px"
---

# Design system: RiskScope

## Overview

**Evidence-led analyst workbench.** This is an Operate interface for repeated investigation in a normal, illuminated office setting: white working surfaces, cool slate navigation, quiet semantic indicators, precise labels and dense but readable records.

The visual system separates observations, automated assessments and analyst decisions. Its distinctive composition is the risk work queue beside an attention rail, followed by a detail workspace that places explicit reasoning and provenance beside attributable decisions. It does not rely on a grid of oversized KPI cards.

Implementation truth lives in `frontend/src/styles.css` and shared components. The emitted `frontend/index.html` retains the original five-part design contract.

## Colors

Blue identifies primary actions, selected navigation and linked records. Cool neutrals carry the structure. Semantic red, amber, muted blue and green appear only with descriptive text, never as the sole carrier of meaning.

Priority and status are deliberately distinct. “Unknown,” “potential,” “verified” and “risk accepted” are labeled states rather than inferred success or danger. Risk data and copy must never turn uncertainty into certainty.

Charts use the separately named `chart-*` series colors above, paired with legend text and accessible snapshot tables. Canvas graph colors distinguish entity types and selection, not severity. These data-visualization roles are intentionally distinct from page chrome.

## Typography

One local system sans family serves headings, controls and data; no remote fonts are loaded. Page headings use a fixed rem scale, dropping to 1.7rem on small screens. Section headings use 1.1rem; table body text is 0.82rem. Data and measurement use tabular numerals where alignment matters.

Prose is generally limited to 74 characters per line. Monospace is reserved for actual JSON/CSV examples and field identifiers, not decorative technical labels.

## Layout

- Desktop: 226px persistent slate sidebar, 43px workstation bar, 30px content inset. At 1600px the sidebar becomes 242px and content inset 38px.
- Dashboard: compact inventory line and priority strip above a flexible queue plus 284px attention rail.
- Risk detail: automated reasoning, factors and evidence next to a 360px analyst-decision column. Below 1250px the decision area follows the evidence.
- Graph: a bounded canvas plus a 285px metadata inspector. Below 1050px the inspector moves below the graph.
- At 760px, the sidebar becomes a menu-controlled drawer under a sticky mobile header; main content uses 17px horizontal insets.
- Tables retain their column structure inside keyboard-focusable horizontal scroll regions. Forms and record facts collapse structurally rather than shrinking text.

## Elevation & Depth

The interface is primarily flat. One-pixel dividers and a second neutral chrome layer establish hierarchy. Ordinary sections have no shadows. Saved-action feedback alone uses an offset soft shadow because it temporarily sits above the workspace.

## Shapes

Controls use 4px corners, buttons 5px, work surfaces 6px. Fine borders and modest radii preserve a precise record-oriented feel. There are no gradients, glass effects or decorative colored rails.

## Components

- **Navigation:** consistent labeled icons, explicit active state, mobile menu, Escape dismissal and route-change focus to main content.
- **Resource table:** API pagination, debounced search, server sorting and filters, persistent URL state for primary lists, explicit row links. Risk selection is limited to five.
- **Evidence detail:** source records, deterministic factor tables, uncertainties, recommendations and analyst overrides are separate sections.
- **Forms:** native labeled controls, metadata-backed validation shape, paginated named relationship selectors, required attribution and reason. Editing is inline, not modal.
- **Workflow controls:** review, acceptance, remediation and verification are distinct. Verification has a required evidence selector and explicit confirmation.
- **Graph:** zoom, pan, fit, backend filtering, truncation warning and a keyboard-accessible node/edge selector exposing the same metadata as pointer interaction.
- **States:** stable skeleton rows, guided empty states, actionable inline errors, disabled pending actions and dismissible saved feedback.
- **Focus/motion:** 3px visible blue outlines. Most transitions are 150–180ms state changes; the single authored entrance belongs to saved feedback. Reduced-motion preferences remove animation and transitions.

## Do's and Don'ts

- Preserve automated scores even when effective priority follows an analyst override.
- Show actual imported or application-generated history; do not synthesize trend points.
- Use “potential attack path,” not confirmed exploitation.
- Keep unknown intelligence explicitly unknown.
- Do not replace contextual evidence with dashboard ornament, marketing copy or security guarantees.
- Do not make irreversible or verification decisions through generic status dropdowns.
- Keep large inventory queries paginated; do not preload every foreign-key record into a selector.
