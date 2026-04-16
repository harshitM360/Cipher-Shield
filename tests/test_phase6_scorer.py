from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detection.rules_engine import RuleEvaluation
from detection.scorer import RiskScorer
from features.extractor import FeatureSummary


FEATURE_DIR = PROJECT_ROOT / 'data' / 'synthetic' / 'feature_summaries'
RULE_HITS_DIR = PROJECT_ROOT / 'data' / 'synthetic' / 'rule_hits'


def _load_feature(name: str) -> FeatureSummary:
    return FeatureSummary.model_validate_json((FEATURE_DIR / f'{name}_features.json').read_text(encoding='utf-8'))


def _load_rule_eval(name: str) -> RuleEvaluation:
    return RuleEvaluation.model_validate_json((RULE_HITS_DIR / f'{name}_rule_hits.json').read_text(encoding='utf-8'))


def test_benign_cases_stay_low_or_info() -> None:
    scorer = RiskScorer()

    office = scorer.score(_load_feature('normal_office_editing'), _load_rule_eval('normal_office_editing'))
    update = scorer.score(_load_feature('software_update_activity'), _load_rule_eval('software_update_activity'))
    rename = scorer.score(_load_feature('admin_bulk_rename'), _load_rule_eval('admin_bulk_rename'))

    assert office.score_breakdown.severity == 'info'
    assert update.score_breakdown.severity == 'info'
    assert rename.score_breakdown.severity in {'info', 'low'}
    assert office.score_breakdown.total_score < 15
    assert update.score_breakdown.total_score < 15
    assert rename.score_breakdown.total_score < 15


def test_malicious_cases_rank_higher_than_benign() -> None:
    scorer = RiskScorer()

    benign = scorer.score(_load_feature('normal_office_editing'), _load_rule_eval('normal_office_editing'))
    word = scorer.score(_load_feature('word_to_powershell'), _load_rule_eval('word_to_powershell'))
    shadow = scorer.score(_load_feature('shadow_copy_delete_and_rename'), _load_rule_eval('shadow_copy_delete_and_rename'))
    rapid = scorer.score(_load_feature('rapid_file_encryption_sim'), _load_rule_eval('rapid_file_encryption_sim'))

    assert word.score_breakdown.total_score > benign.score_breakdown.total_score
    assert shadow.score_breakdown.total_score > word.score_breakdown.total_score
    assert rapid.score_breakdown.total_score > benign.score_breakdown.total_score

    assert word.score_breakdown.severity in {'high', 'critical'}
    assert shadow.score_breakdown.severity == 'critical'
    assert rapid.score_breakdown.severity == 'critical'


def test_high_severity_cases_include_containment_actions() -> None:
    scorer = RiskScorer()
    shadow = scorer.score(_load_feature('shadow_copy_delete_and_rename'), _load_rule_eval('shadow_copy_delete_and_rename'))

    assert any('Isolate the affected host immediately.' == action for action in shadow.recommended_actions)
    assert shadow.score_breakdown.confidence >= 0.75
    assert shadow.attack_tags
