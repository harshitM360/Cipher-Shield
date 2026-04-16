from __future__ import annotations

from pathlib import Path

from detection.rules_engine import RulesEngine


BASE_DIR = Path(__file__).resolve().parent.parent
RULES_DIR = BASE_DIR / "rules"
FEATURES_DIR = BASE_DIR / "data" / "synthetic" / "feature_summaries"


def _titles(evaluation):
    return {match.title for match in evaluation.triggered_rules}


def test_word_to_powershell_triggers_initial_access_style_rules() -> None:
    engine = RulesEngine(RULES_DIR)
    evaluation = engine.evaluate_from_path(FEATURES_DIR / "word_to_powershell_features.json")

    assert _titles(evaluation) == {
        "Suspicious Parent-Child Process Chain",
        "Suspicious Command Execution",
    }
    assert evaluation.highest_level == "high"


def test_shadow_copy_delete_and_rename_triggers_critical_recovery_inhibition() -> None:
    engine = RulesEngine(RULES_DIR)
    evaluation = engine.evaluate_from_path(FEATURES_DIR / "shadow_copy_delete_and_rename_features.json")

    assert _titles(evaluation) == {
        "Suspicious Parent-Child Process Chain",
        "Suspicious Command Execution",
        "Suspicious Shadow Copy Deletion",
    }
    assert evaluation.highest_level == "critical"
    assert "attack.t1490" in evaluation.attack_tags


def test_rapid_file_encryption_hits_impact_rules() -> None:
    engine = RulesEngine(RULES_DIR)
    evaluation = engine.evaluate_from_path(FEATURES_DIR / "rapid_file_encryption_sim_features.json")

    assert _titles(evaluation) == {
        "Mass File Changes in Short Window",
        "Bulk Extension Rename",
        "Suspicious Outbound Connection During File Churn",
    }
    assert evaluation.highest_level == "critical"
    assert "attack.t1486" in evaluation.attack_tags


def test_benign_scenarios_do_not_trigger_rules() -> None:
    engine = RulesEngine(RULES_DIR)
    benign_files = [
        "normal_office_editing_features.json",
        "software_update_activity_features.json",
        "admin_bulk_rename_features.json",
    ]

    for filename in benign_files:
        evaluation = engine.evaluate_from_path(FEATURES_DIR / filename)
        assert evaluation.matched_rule_count == 0, filename
        assert evaluation.highest_level == "info", filename
