from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.summarizer import SocReport, SocReportGenerator, generate_all_soc_reports


def test_generate_single_soc_report() -> None:
    generator = SocReportGenerator()
    report = generator.generate_from_paths(
        ROOT / 'data' / 'synthetic' / 'scenarios' / 'shadow_copy_delete_and_rename.json',
        ROOT / 'data' / 'synthetic' / 'feature_summaries' / 'shadow_copy_delete_and_rename_features.json',
        ROOT / 'data' / 'synthetic' / 'rule_hits' / 'shadow_copy_delete_and_rename_rule_hits.json',
        ROOT / 'data' / 'synthetic' / 'risk_assessments' / 'shadow_copy_delete_and_rename_risk_assessment.json',
        ROOT / 'data' / 'synthetic' / 'mitre_mappings' / 'shadow_copy_delete_and_rename_mitre_mapping.json',
    )

    assert isinstance(report, SocReport)
    assert report.severity == 'critical'
    assert report.incident_classification == 'Likely ransomware impact activity'
    assert any(rule.title == 'Suspicious Shadow Copy Deletion' for rule in report.triggered_rules)
    assert any(tech.technique_id == 'T1490' for tech in report.mitre_attack_mapping)
    assert report.recommended_actions


def test_generate_all_soc_reports() -> None:
    output_dir = ROOT / 'data' / 'synthetic' / 'soc_reports'
    paths = generate_all_soc_reports(
        ROOT / 'data' / 'synthetic' / 'scenarios',
        ROOT / 'data' / 'synthetic' / 'feature_summaries',
        ROOT / 'data' / 'synthetic' / 'rule_hits',
        ROOT / 'data' / 'synthetic' / 'risk_assessments',
        ROOT / 'data' / 'synthetic' / 'mitre_mappings',
        output_dir,
    )

    assert len(paths) == 6
    assert all(path.exists() for path in paths)
    assert (output_dir / 'word_to_powershell_soc_report.json').exists()
