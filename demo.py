from __future__ import annotations

import argparse
import json
from pathlib import Path

from api.routes import run_pipeline


PROJECT_ROOT = Path(__file__).resolve().parent
DATA_ROOT = PROJECT_ROOT / "data" / "synthetic"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one ransomware copilot scenario end to end.")
    parser.add_argument(
        "--scenario",
        default="shadow_copy_delete_and_rename",
        help="Scenario file stem to analyze.",
    )
    parser.add_argument(
        "--no-persist",
        action="store_true",
        help="Run analysis without writing pipeline outputs to disk.",
    )
    args = parser.parse_args()

    payload = run_pipeline(args.scenario, persist=not args.no_persist)
    soc_report = payload["soc_report"]
    risk = payload["risk_assessment"]
    mitre = payload["mitre_mapping"]

    print("=" * 72)
    print("Ransomware Copilot Demo")
    print("=" * 72)
    print(f"Scenario:   {payload['scenario_name']}")
    print(f"Severity:   {soc_report['severity']}")
    print(f"Confidence: {soc_report['confidence']}")
    print(f"Summary:    {soc_report['executive_summary']}")
    print("
Recommended actions:")
    for action in soc_report["recommended_actions"]:
        print(f"- {action}")
    print("
Mapped ATT&CK techniques:")
    for technique in mitre["mapped_techniques"]:
        print(f"- {technique['technique_id']}: {technique['technique_name']}")

    if not args.no_persist:
        out_path = DATA_ROOT / "api_outputs" / f"{args.scenario}_api_output.json"
        print(f"
Saved full pipeline payload to: {out_path}")
    else:
        print("
Run completed without writing files.")

    print("
Compact JSON preview:")
    preview = {
        "scenario_name": payload["scenario_name"],
        "severity": risk["score_breakdown"]["severity"],
        "total_score": risk["score_breakdown"]["total_score"],
        "report_summary": soc_report["executive_summary"],
    }
    print(json.dumps(preview, indent=2))


if __name__ == "__main__":
    main()
