from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api.routes import run_pipeline


def test_full_pipeline_integration_for_critical_scenario() -> None:
    payload = run_pipeline("shadow_copy_delete_and_rename", persist=False)

    assert payload["scenario_name"] == "shadow_copy_delete_and_rename"
    assert payload["risk_assessment"]["score_breakdown"]["severity"] == "critical"
    assert payload["soc_report"]["severity"] == "critical"
    assert payload["mitre_mapping"]["mapped_techniques"]
    assert any(
        item["technique_id"] == "T1490"
        for item in payload["mitre_mapping"]["mapped_techniques"]
    )
    assert payload["soc_report"]["recommended_actions"]


def test_demo_payload_is_json_serializable() -> None:
    payload = run_pipeline("word_to_powershell", persist=False)
    serialized = json.dumps(payload)
    assert "word_to_powershell" in serialized
