from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.app import app


client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json() == {'status': 'ok'}


def test_scenarios_endpoint_lists_known_scenarios() -> None:
    response = client.get('/scenarios')
    assert response.status_code == 200
    payload = response.json()
    assert 'scenarios' in payload
    assert 'word_to_powershell' in payload['scenarios']
    assert 'normal_office_editing' in payload['scenarios']


def test_analyze_endpoint_returns_full_payload() -> None:
    response = client.post('/analyze/word_to_powershell')
    assert response.status_code == 200
    payload = response.json()
    assert payload['scenario_name'] == 'word_to_powershell'
    assert 'feature_summary' in payload
    assert 'rule_evaluation' in payload
    assert 'risk_assessment' in payload
    assert 'mitre_mapping' in payload
    assert 'soc_report' in payload
    assert payload['soc_report']['severity'] in {'high', 'critical'}


def test_reports_endpoint_returns_saved_soc_report() -> None:
    client.post('/analyze/shadow_copy_delete_and_rename')
    response = client.get('/reports/shadow_copy_delete_and_rename')
    assert response.status_code == 200
    payload = response.json()
    assert payload['scenario_name'] == 'Shadow copy deletion and mass rename'
    assert payload['severity'] == 'critical'
