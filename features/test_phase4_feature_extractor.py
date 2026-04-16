from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from features import FeatureExtractor, extract_all_event_streams  # noqa: E402


GENERATED_DIR = ROOT / 'data' / 'synthetic' / 'generated'
FEATURE_DIR = ROOT / 'data' / 'synthetic' / 'feature_summaries'


def test_feature_extractor_distinguishes_benign_and_malicious_patterns() -> None:
    extractor = FeatureExtractor()

    benign = extractor.extract_from_path(GENERATED_DIR / 'normal_office_editing_events.json')
    word_chain = extractor.extract_from_path(GENERATED_DIR / 'word_to_powershell_events.json')
    shadow = extractor.extract_from_path(GENERATED_DIR / 'shadow_copy_delete_and_rename_events.json')
    rapid = extractor.extract_from_path(GENERATED_DIR / 'rapid_file_encryption_sim_events.json')

    assert benign.total_events == 4
    assert benign.file_modify_count == 2
    assert benign.file_activity_count == 3
    assert benign.backup_delete_attempt is False
    assert benign.suspicious_parent_child is False
    assert benign.unique_files_touched == 3

    assert word_chain.suspicious_parent_child is True
    assert word_chain.command_exec_count == 1
    assert word_chain.suspicious_command is True
    assert word_chain.backup_delete_attempt is False

    assert shadow.backup_delete_attempt is True
    assert shadow.file_rename_count == 2
    assert shadow.extension_change_count == 2
    assert shadow.unique_directories_touched == 1

    assert rapid.network_connection_count == 1
    assert rapid.file_rename_count == 3
    assert rapid.max_file_events_in_10s >= shadow.max_file_events_in_10s
    assert rapid.burst_activity_score > benign.burst_activity_score


def test_extract_all_event_streams_writes_feature_summaries() -> None:
    saved_paths = extract_all_event_streams(GENERATED_DIR, FEATURE_DIR)

    assert len(saved_paths) == 6
    target = FEATURE_DIR / 'shadow_copy_delete_and_rename_features.json'
    assert target.exists()

    payload = json.loads(target.read_text(encoding='utf-8'))
    assert payload['scenario_id'] == 'scenario-bundle--malicious-002'
    assert payload['backup_delete_attempt'] is True
    assert payload['event_type_counts']['file_rename'] == 2
