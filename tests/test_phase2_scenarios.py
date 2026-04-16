from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from schemas import ScenarioBundle  # noqa: E402


SCENARIO_DIR = ROOT / 'data' / 'synthetic' / 'scenarios'


def test_all_phase2_scenarios_validate() -> None:
    scenario_files = sorted(SCENARIO_DIR.glob('*.json'))
    assert len(scenario_files) == 6

    bundles = []
    for scenario_file in scenario_files:
        payload = json.loads(scenario_file.read_text(encoding='utf-8'))
        bundles.append(ScenarioBundle.model_validate(payload))

    malicious_count = sum(bundle.is_malicious for bundle in bundles)
    benign_count = len(bundles) - malicious_count

    assert malicious_count == 3
    assert benign_count == 3


def test_malicious_scenarios_have_expected_attack_context() -> None:
    scenario_file = SCENARIO_DIR / 'shadow_copy_delete_and_rename.json'
    payload = json.loads(scenario_file.read_text(encoding='utf-8'))
    bundle = ScenarioBundle.model_validate(payload)

    assert bundle.expected_findings.severity == 'critical'
    assert 'T1490' in bundle.expected_findings.attack_techniques
    assert bundle.timeline[1].event_ref == 'event--002'
