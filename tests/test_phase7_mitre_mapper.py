from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detection.mitre_mapper import MitreMapper


RISK_DIR = PROJECT_ROOT / 'data' / 'synthetic' / 'risk_assessments'
RULE_HITS_DIR = PROJECT_ROOT / 'data' / 'synthetic' / 'rule_hits'


def _map(name: str):
    mapper = MitreMapper()
    return mapper.map_from_paths(
        RULE_HITS_DIR / f'{name}_rule_hits.json',
        RISK_DIR / f'{name}_risk_assessment.json',
    )


def test_benign_cases_have_no_attack_mappings() -> None:
    office = _map('normal_office_editing')
    update = _map('software_update_activity')
    rename = _map('admin_bulk_rename')

    assert office.mapped_techniques == []
    assert update.mapped_techniques == []
    assert rename.mapped_techniques == []
    assert office.severity == 'info'



def test_word_to_powershell_maps_execution_techniques() -> None:
    report = _map('word_to_powershell')
    technique_ids = {item.technique_id for item in report.mapped_techniques}

    assert 'T1059.001' in technique_ids
    assert 'T1204' in technique_ids
    assert report.severity in {'high', 'critical'}



def test_shadow_copy_case_maps_recovery_inhibition_and_encryption_impact() -> None:
    report = _map('shadow_copy_delete_and_rename')
    technique_ids = {item.technique_id for item in report.mapped_techniques}

    assert 'T1490' in technique_ids
    assert 'T1486' in technique_ids
    assert report.severity == 'critical'



def test_rapid_file_encryption_maps_impact_and_network_transfer() -> None:
    report = _map('rapid_file_encryption_sim')
    technique_ids = {item.technique_id for item in report.mapped_techniques}

    assert 'T1486' in technique_ids
    assert 'T1105' in technique_ids
    assert report.summary
