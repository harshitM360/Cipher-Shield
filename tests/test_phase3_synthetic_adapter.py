from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapters import SyntheticScenarioAdapter, generate_all_scenarios  # noqa: E402
from schemas import EventType, ScenarioStage  # noqa: E402


SCENARIO_DIR = ROOT / 'data' / 'synthetic' / 'scenarios'
GENERATED_DIR = ROOT / 'data' / 'synthetic' / 'generated'


def test_word_to_powershell_generates_canonical_events() -> None:
    adapter = SyntheticScenarioAdapter()
    bundle = adapter.load_bundle(SCENARIO_DIR / 'word_to_powershell.json')

    events = adapter.generate_events(bundle)

    assert len(events) == len(bundle.timeline)
    assert events[0].event_type == EventType.PROCESS_CREATE
    assert events[1].actor.process.name == 'powershell.exe'
    assert events[1].process is not None
    assert events[1].process.parent_process.name == 'winword.exe'
    assert events[1].scenario.stage == ScenarioStage.PRE_IMPACT
    assert events[2].scenario.stage == ScenarioStage.PRE_IMPACT
    assert events[2].actor.process.command_line is not None

    shadow_bundle = adapter.load_bundle(SCENARIO_DIR / 'shadow_copy_delete_and_rename.json')
    shadow_events = adapter.generate_events(shadow_bundle)
    assert shadow_events[3].scenario.stage == ScenarioStage.IMPACT
    assert shadow_events[3].file is not None
    assert shadow_events[3].file.path is not None


def test_generate_all_scenarios_writes_event_streams() -> None:
    generated_paths = generate_all_scenarios(SCENARIO_DIR, GENERATED_DIR)

    assert len(generated_paths) == 6
    target = GENERATED_DIR / 'shadow_copy_delete_and_rename_events.json'
    assert target.exists()

    payload = json.loads(target.read_text(encoding='utf-8'))
    assert len(payload) == 5
    assert payload[1]['event_type'] == 'backup_delete_attempt'
    assert payload[1]['scenario']['stage'] == 'pre-impact'
    assert payload[3]['scenario']['stage'] == 'impact'
