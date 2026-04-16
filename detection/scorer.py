from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from detection.rules_engine import RuleEvaluation
from features.extractor import FeatureSummary
from schemas import Severity


_RULE_TITLE_WEIGHTS: dict[str, int] = {
    "Suspicious Shadow Copy Deletion": 40,
    "Mass File Changes in Short Window": 30,
    "Bulk Extension Rename": 25,
    "Suspicious Parent-Child Process Chain": 18,
    "Suspicious Command Execution": 18,
    "Suspicious Outbound Connection During File Churn": 15,
}


class ScoreBreakdown(BaseModel):
    """Explainable scoring breakdown used by the ransomware risk scorer."""

    model_config = ConfigDict(extra="forbid")

    rule_score: int
    behavior_score: int
    total_score: int
    severity: str
    confidence: float
    contributing_factors: list[dict[str, Any]] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    """Final weighted risk assessment for one scenario."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    hostname: str
    labels: list[str] = Field(default_factory=list)
    matched_rule_count: int
    highest_rule_level: str
    attack_tags: list[str] = Field(default_factory=list)
    score_breakdown: ScoreBreakdown
    recommended_actions: list[str] = Field(default_factory=list)


class RiskScorer:
    """Transparent weighted risk scorer for Phase 6."""

    def score(self, summary: FeatureSummary, evaluation: RuleEvaluation) -> RiskAssessment:
        if summary.scenario_id != evaluation.scenario_id:
            raise ValueError(
                "Feature summary and rule evaluation must belong to the same scenario. "
                f"Got {summary.scenario_id!r} and {evaluation.scenario_id!r}."
            )

        contributing_factors: list[dict[str, Any]] = []
        rule_score = 0
        for match in evaluation.triggered_rules:
            weight = _RULE_TITLE_WEIGHTS.get(match.title, 10)
            rule_score += weight
            contributing_factors.append(
                {
                    "type": "rule",
                    "name": match.title,
                    "weight": weight,
                    "evidence": match.evidence,
                }
            )

        behavior_score = 0
        behavior_score += self._add_behavior_factor(
            contributing_factors,
            "Backup deletion attempt present",
            10 if summary.backup_delete_attempt else 0,
            {"backup_delete_attempt_count": summary.backup_delete_attempt_count},
        )
        behavior_score += self._add_behavior_factor(
            contributing_factors,
            "Suspicious parent-child process chain",
            8 if summary.suspicious_parent_child else 0,
            {"suspicious_parent_child_count": summary.suspicious_parent_child_count},
        )
        behavior_score += self._add_behavior_factor(
            contributing_factors,
            "Suspicious command usage",
            8 if summary.suspicious_command else 0,
            {"suspicious_command_count": summary.suspicious_command_count},
        )
        behavior_score += self._add_behavior_factor(
            contributing_factors,
            "Office application spawned suspicious scripting activity",
            10 if summary.suspicious_parent_child and summary.suspicious_command else 0,
            {
                "suspicious_parent_child_count": summary.suspicious_parent_child_count,
                "suspicious_command_count": summary.suspicious_command_count,
            },
        )
        behavior_score += self._add_behavior_factor(
            contributing_factors,
            "High file activity burst",
            10 if summary.max_file_events_in_10s >= 5 else 0,
            {
                "max_file_events_in_10s": summary.max_file_events_in_10s,
                "file_activity_count": summary.file_activity_count,
            },
        )
        behavior_score += self._add_behavior_factor(
            contributing_factors,
            "Multiple extension changes",
            10 if summary.extension_change_count >= 2 else 0,
            {"extension_change_count": summary.extension_change_count},
        )
        behavior_score += self._add_behavior_factor(
            contributing_factors,
            "Sensitive user directories touched",
            5 if summary.sensitive_directory_touch_count >= 2 else 0,
            {"sensitive_directory_touch_count": summary.sensitive_directory_touch_count},
        )
        behavior_score += self._add_behavior_factor(
            contributing_factors,
            "Network activity during file churn",
            8 if summary.network_connection_count >= 1 and summary.file_activity_count >= 4 else 0,
            {
                "network_connection_count": summary.network_connection_count,
                "file_activity_count": summary.file_activity_count,
            },
        )
        behavior_score += self._add_behavior_factor(
            contributing_factors,
            "Very high burst activity score",
            5 if summary.burst_activity_score >= 5.0 else 0,
            {"burst_activity_score": summary.burst_activity_score},
        )

        total_score = min(rule_score + behavior_score, 100)
        severity = self._score_to_severity(total_score)
        confidence = self._score_to_confidence(total_score, evaluation.matched_rule_count)

        return RiskAssessment(
            scenario_id=summary.scenario_id,
            hostname=summary.hostname,
            labels=list(summary.labels),
            matched_rule_count=evaluation.matched_rule_count,
            highest_rule_level=evaluation.highest_level,
            attack_tags=list(evaluation.attack_tags),
            score_breakdown=ScoreBreakdown(
                rule_score=rule_score,
                behavior_score=behavior_score,
                total_score=total_score,
                severity=severity,
                confidence=confidence,
                contributing_factors=contributing_factors,
            ),
            recommended_actions=self._recommended_actions(summary, evaluation, severity),
        )

    def score_from_paths(self, feature_path: str | Path, rule_eval_path: str | Path) -> RiskAssessment:
        summary = FeatureSummary.model_validate(json.loads(Path(feature_path).read_text(encoding="utf-8")))
        evaluation = RuleEvaluation.model_validate(json.loads(Path(rule_eval_path).read_text(encoding="utf-8")))
        return self.score(summary, evaluation)

    def save_assessment(self, assessment: RiskAssessment, output_path: str | Path, *, indent: int = 2) -> Path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(assessment.model_dump(mode="json"), indent=indent), encoding="utf-8")
        return output

    def score_and_save(self, feature_path: str | Path, rule_eval_path: str | Path, output_path: str | Path) -> RiskAssessment:
        assessment = self.score_from_paths(feature_path, rule_eval_path)
        self.save_assessment(assessment, output_path)
        return assessment

    @staticmethod
    def _add_behavior_factor(
        contributing_factors: list[dict[str, Any]],
        name: str,
        weight: int,
        evidence: dict[str, Any],
    ) -> int:
        if weight <= 0:
            return 0
        contributing_factors.append(
            {
                "type": "behavior",
                "name": name,
                "weight": weight,
                "evidence": evidence,
            }
        )
        return weight

    @staticmethod
    def _score_to_severity(score: int) -> str:
        if score >= 85:
            return Severity.CRITICAL.value
        if score >= 60:
            return Severity.HIGH.value
        if score >= 35:
            return Severity.MEDIUM.value
        if score >= 15:
            return Severity.LOW.value
        return Severity.INFO.value

    @staticmethod
    def _score_to_confidence(score: int, matched_rule_count: int) -> float:
        confidence = min(0.99, 0.15 + (score / 100.0) * 0.7 + min(matched_rule_count, 4) * 0.04)
        return round(confidence, 3)

    @staticmethod
    def _recommended_actions(summary: FeatureSummary, evaluation: RuleEvaluation, severity: str) -> list[str]:
        actions: list[str] = []
        if severity in {Severity.HIGH.value, Severity.CRITICAL.value}:
            actions.append("Isolate the affected host immediately.")
            actions.append("Preserve volatile evidence and collect forensic artifacts.")
        if summary.backup_delete_attempt:
            actions.append("Protect recovery infrastructure and verify shadow copy availability.")
        if summary.suspicious_parent_child or summary.suspicious_command:
            actions.append("Review the suspicious process tree and terminate malicious processes if confirmed.")
        if summary.file_activity_count >= 4 or summary.extension_change_count >= 2:
            actions.append("Assess impacted user files and block further write activity if possible.")
        if summary.network_connection_count >= 1:
            actions.append("Inspect outbound connections for potential command-and-control or staging activity.")
        if not actions:
            actions.append("Continue monitoring; current activity does not justify containment.")

        # Keep order stable while removing duplicates.
        stable_actions: list[str] = []
        seen: set[str] = set()
        for action in actions:
            if action not in seen:
                stable_actions.append(action)
                seen.add(action)
        return stable_actions


def score_all_rule_evaluations(
    feature_dir: str | Path,
    rule_hits_dir: str | Path,
    output_dir: str | Path,
) -> list[Path]:
    """Score every saved rule evaluation against its matching feature summary."""

    scorer = RiskScorer()
    feature_root = Path(feature_dir)
    rule_root = Path(rule_hits_dir)
    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)

    saved_paths: list[Path] = []
    for feature_path in sorted(feature_root.glob("*_features.json")):
        scenario_stub = feature_path.name.replace("_features.json", "")
        rule_eval_path = rule_root / f"{scenario_stub}_rule_hits.json"
        if not rule_eval_path.exists():
            raise FileNotFoundError(f"Missing rule evaluation for feature summary: {rule_eval_path}")
        output_path = output_root / f"{scenario_stub}_risk_assessment.json"
        scorer.score_and_save(feature_path, rule_eval_path, output_path)
        saved_paths.append(output_path)
    return saved_paths
