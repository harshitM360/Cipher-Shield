from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import streamlit as st

from api.routes import run_pipeline

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_ROOT = PROJECT_ROOT / "data" / "synthetic"
SCENARIOS_DIR = DATA_ROOT / "scenarios"
SOC_REPORTS_DIR = DATA_ROOT / "soc_reports"


@st.cache_data(show_spinner=False)
def list_scenarios() -> list[str]:
    return sorted(path.stem for path in SCENARIOS_DIR.glob("*.json"))


@st.cache_data(show_spinner=False)
def load_saved_report(scenario_name: str) -> dict[str, Any] | None:
    report_path = SOC_REPORTS_DIR / f"{scenario_name}_soc_report.json"
    if not report_path.exists():
        return None
    return json.loads(report_path.read_text(encoding="utf-8"))


def render_rule_table(payload: dict[str, Any]) -> None:
    rules = payload["soc_report"].get("triggered_rules", [])
    if not rules:
        st.info("No detection rules were triggered for this scenario.")
        return

    table_rows = [
        {
            "Title": rule["title"],
            "Level": rule["level"],
            "Description": rule["description"],
        }
        for rule in rules
    ]
    st.dataframe(table_rows, use_container_width=True, hide_index=True)


def render_mitre_table(payload: dict[str, Any]) -> None:
    techniques = payload["mitre_mapping"].get("mapped_techniques", [])
    if not techniques:
        st.info("No ATT&CK techniques were mapped for this scenario.")
        return

    table_rows = [
        {
            "Technique ID": item["technique_id"],
            "Technique": item["technique_name"],
            "Tactics": ", ".join(item.get("tactics", [])),
            "Confidence": item["confidence"],
        }
        for item in techniques
    ]
    st.dataframe(table_rows, use_container_width=True, hide_index=True)


def render_actions(payload: dict[str, Any]) -> None:
    actions = payload["soc_report"].get("recommended_actions", [])
    if not actions:
        st.info("No response actions were recommended.")
        return
    for action in actions:
        st.write(f"- {action}")


def render_evidence(payload: dict[str, Any]) -> None:
    evidence = payload["soc_report"].get("key_evidence", [])
    if not evidence:
        st.info("No supporting evidence was generated.")
        return
    for item in evidence:
        st.write(f"- {item}")


def main() -> None:
    st.set_page_config(
        page_title="Ransomware Copilot",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("🛡️ Ransomware Copilot")
    st.caption("Explainable SOC copilot for ransomware detection using synthetic endpoint scenarios.")

    scenarios = list_scenarios()
    if not scenarios:
        st.error("No scenarios were found in data/synthetic/scenarios/.")
        return

    with st.sidebar:
        st.header("Run analysis")
        scenario_name = st.selectbox("Scenario", scenarios, index=scenarios.index("shadow_copy_delete_and_rename") if "shadow_copy_delete_and_rename" in scenarios else 0)
        persist_outputs = st.checkbox("Persist pipeline outputs", value=True)
        run_clicked = st.button("Analyze scenario", type="primary", use_container_width=True)

        st.divider()
        st.header("Saved report")
        saved_report = load_saved_report(scenario_name)
        if saved_report:
            st.success("Saved SOC report found.")
        else:
            st.warning("No saved SOC report yet for this scenario.")

    payload: dict[str, Any] | None = None
    if run_clicked:
        with st.spinner("Running pipeline..."):
            payload = run_pipeline(scenario_name, persist=persist_outputs)
        st.success("Scenario analyzed successfully.")
    elif saved_report:
        # Build a lightweight payload when only a saved report exists.
        report_path = SOC_REPORTS_DIR / f"{scenario_name}_soc_report.json"
        payload = {
            "scenario_name": scenario_name,
            "soc_report": saved_report,
            "mitre_mapping": {"mapped_techniques": saved_report.get("mitre_attack_mapping", [])},
            "risk_assessment": {
                "score_breakdown": {
                    "severity": saved_report.get("severity", "info"),
                    "confidence": saved_report.get("confidence", 0.0),
                    "total_score": None,
                }
            },
        }
        st.info(f"Showing saved report from {report_path.relative_to(PROJECT_ROOT)}")

    if not payload:
        st.info("Choose a scenario and click **Analyze scenario** to run the pipeline.")
        return

    soc_report = payload["soc_report"]
    risk = payload.get("risk_assessment", {}).get("score_breakdown", {})

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Severity", soc_report.get("severity", "unknown").upper())
    col2.metric("Confidence", soc_report.get("confidence", 0.0))
    total_score = risk.get("total_score")
    col3.metric("Total Score", total_score if total_score is not None else "saved")
    col4.metric("Rules Triggered", len(soc_report.get("triggered_rules", [])))

    st.subheader("Executive summary")
    st.write(soc_report.get("executive_summary", "No summary available."))

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Evidence",
        "Rules",
        "ATT&CK",
        "Actions",
        "Raw JSON",
    ])

    with tab1:
        render_evidence(payload)

    with tab2:
        render_rule_table(payload)

    with tab3:
        render_mitre_table(payload)

    with tab4:
        render_actions(payload)

    with tab5:
        st.json(payload, expanded=False)


if __name__ == "__main__":
    main()
