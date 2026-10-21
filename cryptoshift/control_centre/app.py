"""Streamlit Control Centre — CryptoShift review and approval dashboard.

IMPORT BOUNDARY: This module reads artifact files only.
It must NOT import any engine modules.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st

ARTIFACTS_DIR = Path(
    st.sidebar.text_input(
        "Artifacts directory",
        value="artifacts",
        help="Path to CryptoShift artifacts directory",
    )
)

st.set_page_config(
    page_title="CryptoShift Control Centre",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)


def load_json(filepath: Path) -> Any:
    """Load a JSON file, returning None if it doesn't exist."""
    if filepath.exists():
        with open(filepath, encoding="utf-8") as f:
            return json.load(f)
    return None


def save_decision(finding_id: str, decision: str, reviewer: str, notes: str) -> None:
    """Write a schema-validated decision file."""
    decisions_dir = ARTIFACTS_DIR / "decisions"
    decisions_dir.mkdir(parents=True, exist_ok=True)

    decision_data = {
        "schema_version": "1.0.0",
        "finding_id": finding_id,
        "reviewer": reviewer,
        "decision": decision,
        "notes": notes,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    filepath = decisions_dir / f"{finding_id}.json"
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(decision_data, f, indent=2, sort_keys=True)


def get_risk_color(score: float) -> str:
    """Return a color indicator based on risk score."""
    if score >= 7:
        return "🔴"
    elif score >= 4:
        return "🟡"
    return "🟢"


st.sidebar.title("🔐 CryptoShift")
st.sidebar.markdown("**Control Centre**")
st.sidebar.markdown("---")

reviewer_name = st.sidebar.text_input("Reviewer name", value="reviewer")

page = st.sidebar.radio(
    "Navigate",
    ["📋 Backlog", "🔍 Finding Detail", "📊 Progress"],
)


def render_backlog() -> None:
    """Render the risk-prioritized backlog view."""
    st.header("📋 Migration Backlog")

    enriched_path = ARTIFACTS_DIR / "enriched_cbom.json"
    data = load_json(enriched_path)

    if data is None:
        st.warning(
            f"No enriched CBOM found at `{enriched_path}`. "
            "Run `cryptoshift scan` and `cryptoshift enrich` first."
        )
        return

    findings = data if isinstance(data, list) else [data]
    findings.sort(key=lambda f: f.get("risk", {}).get("score", 0), reverse=True)

    st.markdown(f"**{len(findings)} findings** sorted by risk score (highest first)")

    for finding in findings:
        risk = finding.get("risk", {})
        score = risk.get("score", 0)
        fid = finding.get("finding_id", "unknown")
        algo = finding.get("algorithm", "unknown")
        role = finding.get("role", "unknown")
        filepath = finding.get("file", "unknown")
        line = finding.get("line", 0)

        decision_file = ARTIFACTS_DIR / "decisions" / f"{fid}.json"
        decision_data = load_json(decision_file)
        decision_status = decision_data.get("decision", "pending") if decision_data else "pending"

        status_badge = {
            "approved": "✅",
            "rejected": "❌",
            "deferred": "⏸️",
            "pending": "⏳",
        }.get(decision_status, "⏳")

        with st.expander(
            f"{get_risk_color(score)} [{score:.1f}] {fid} — {algo} ({role}) "
            f"at {filepath}:{line} {status_badge}"
        ):
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Sensitivity", f"{risk.get('sensitivity', 0)}/10")
            with col2:
                st.metric("Criticality", f"{risk.get('criticality', 0)}/10")
            with col3:
                st.metric("Lifespan (HNDL)", f"{risk.get('lifespan', 0)}/10")

            st.text(f"AST Node: {finding.get('ast_node', 'N/A')}")
            st.text(f"Status: {finding.get('status', 'N/A')}")
            st.text(f"Role Confidence: {finding.get('role_confidence', 'N/A')}")

            if st.button(f"View details for {fid}", key=f"detail_{fid}"):
                st.session_state["selected_finding"] = fid


def render_finding_detail() -> None:
    """Render detailed finding view with diff and approval controls."""
    st.header("🔍 Finding Detail")

    finding_id = st.text_input(
        "Finding ID",
        value=st.session_state.get("selected_finding", ""),
        placeholder="e.g., f-0042",
    )

    if not finding_id:
        st.info("Enter a finding ID to view details.")
        return

    enriched_path = ARTIFACTS_DIR / "enriched_cbom.json"
    data = load_json(enriched_path)
    if data is None:
        st.warning("No enriched CBOM found.")
        return

    findings = data if isinstance(data, list) else [data]
    finding = next((f for f in findings if f.get("finding_id") == finding_id), None)

    if finding is None:
        st.error(f"Finding '{finding_id}' not found in enriched CBOM.")
        return

    st.subheader("Finding Information")
    st.json(finding)

    candidate_path = ARTIFACTS_DIR / "candidates" / finding_id / "candidate.json"
    candidate = load_json(candidate_path)

    if candidate:
        st.subheader("Transformation Candidate")
        st.markdown(f"**Template:** `{candidate.get('template_id', 'N/A')}`")
        st.markdown(f"**Rationale:** {candidate.get('rationale', 'N/A')}")

        patch = candidate.get("patch", "")
        if patch:
            st.subheader("Side-by-Side Diff")
            st.code(patch, language="diff")

    report_path = ARTIFACTS_DIR / "candidates" / finding_id / "verification_report.json"
    report = load_json(report_path)

    if report:
        st.subheader("Verification Results")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### Track A — Functional")
            track_a = report.get("trackA", {})
            status_a = track_a.get("status", "N/A")
            st.markdown(f"**Status:** {'✅' if status_a == 'pass' else '❌'} {status_a}")
            passed = track_a.get("tests_passed", 0)
            run = track_a.get("tests_run", 0)
            st.markdown(f"**Tests:** {passed}/{run}")

        with col2:
            st.markdown("#### Track B — Assurance")
            track_b = report.get("trackB", {})
            status_b = track_b.get("status", "N/A")
            st.markdown(f"**Status:** {'✅' if status_b == 'pass' else '❌'} {status_b}")
            kat = track_b.get("kat_results", {})
            st.markdown(f"**KATs:** {kat.get('passed', 0)}/{kat.get('total', 0)}")
            lint = track_b.get("lint_results", {})
            st.markdown(f"**Lint:** {lint.get('passed', 0)}/{lint.get('total_rules', 0)}")

    st.subheader("Decision")
    existing = load_json(ARTIFACTS_DIR / "decisions" / f"{finding_id}.json")
    if existing:
        st.info(
            f"Existing decision: **{existing['decision']}** "
            f"by {existing['reviewer']} at {existing['timestamp']}"
        )

    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("✅ Approve", key=f"approve_{finding_id}", type="primary"):
            notes = st.session_state.get(f"notes_{finding_id}", "")
            save_decision(finding_id, "approved", reviewer_name, notes)
            st.success(f"Finding {finding_id} approved!")
            st.rerun()
    with col2:
        if st.button("❌ Reject", key=f"reject_{finding_id}"):
            notes = st.session_state.get(f"notes_{finding_id}", "")
            save_decision(finding_id, "rejected", reviewer_name, notes)
            st.warning(f"Finding {finding_id} rejected.")
            st.rerun()
    with col3:
        if st.button("⏸️ Defer", key=f"defer_{finding_id}"):
            notes = st.session_state.get(f"notes_{finding_id}", "")
            save_decision(finding_id, "deferred", reviewer_name, notes)
            st.info(f"Finding {finding_id} deferred.")
            st.rerun()

    st.text_area("Notes", key=f"notes_{finding_id}", placeholder="Reviewer notes...")


def render_progress() -> None:
    """Render migration progress summary."""
    st.header("📊 Migration Progress")

    enriched_path = ARTIFACTS_DIR / "enriched_cbom.json"
    data = load_json(enriched_path)

    if data is None:
        st.warning("No enriched CBOM found. Run the pipeline first.")
        return

    findings = data if isinstance(data, list) else [data]
    total = len(findings)

    decisions_dir = ARTIFACTS_DIR / "decisions"
    approved = 0
    rejected = 0
    deferred = 0

    if decisions_dir.exists():
        for decision_file in decisions_dir.glob("*.json"):
            decision = load_json(decision_file)
            if decision:
                status = decision.get("decision", "")
                if status == "approved":
                    approved += 1
                elif status == "rejected":
                    rejected += 1
                elif status == "deferred":
                    deferred += 1

    pending = total - approved - rejected - deferred
    migrated_pct = (approved / total * 100) if total > 0 else 0

    st.progress(migrated_pct / 100, text=f"{migrated_pct:.0f}% migrated")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("✅ Approved", approved)
    with col2:
        st.metric("❌ Rejected", rejected)
    with col3:
        st.metric("⏸️ Deferred", deferred)
    with col4:
        st.metric("⏳ Pending", pending)

    st.subheader("Remaining by Risk Tier")
    pending_findings = [
        f
        for f in findings
        if not (ARTIFACTS_DIR / "decisions" / f"{f.get('finding_id', '')}.json").exists()
    ]

    high = len([f for f in pending_findings if f.get("risk", {}).get("score", 0) >= 7])
    medium = len([f for f in pending_findings if 4 <= f.get("risk", {}).get("score", 0) < 7])
    low = len([f for f in pending_findings if f.get("risk", {}).get("score", 0) < 4])

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("🔴 High Risk", high)
    with col2:
        st.metric("🟡 Medium Risk", medium)
    with col3:
        st.metric("🟢 Low Risk", low)


if page == "📋 Backlog":
    render_backlog()
elif page == "🔍 Finding Detail":
    render_finding_detail()
elif page == "📊 Progress":
    render_progress()
