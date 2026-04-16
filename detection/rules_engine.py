from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

import yaml
from pydantic import BaseModel, ConfigDict, Field

from features.extractor import FeatureSummary
from schemas import Severity


_LEVEL_ORDER: dict[str, int] = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


class RuleMetadata(BaseModel):
    """Minimal Sigma-style rule metadata used by the Phase 5 engine."""

    model_config = ConfigDict(extra="allow")

    title: str
    id: str
    status: str
    description: str
    logsource: dict[str, Any] = Field(default_factory=dict)
    detection: dict[str, Any] = Field(default_factory=dict)
    level: str
    tags: list[str] = Field(default_factory=list)


class RuleMatch(BaseModel):
    """A single triggered rule with structured evidence."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    title: str
    level: str
    description: str
    tags: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class RuleEvaluation(BaseModel):
    """Combined rule results for one feature summary."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    hostname: str
    labels: list[str] = Field(default_factory=list)
    triggered_rules: list[RuleMatch] = Field(default_factory=list)
    matched_rule_count: int
    highest_level: str
    attack_tags: list[str] = Field(default_factory=list)


class RulesEngine:
    """Evaluate Phase 5 ransomware rules over extracted behavior features."""

    def __init__(self, rules_dir: str | Path):
        self.rules_dir = Path(rules_dir)
        self.rules = self._load_rules(self.rules_dir)

    @staticmethod
    def _load_rules(rules_dir: Path) -> list[RuleMetadata]:
        if not rules_dir.exists():
            raise FileNotFoundError(f"Rules directory does not exist: {rules_dir}")

        rules: list[RuleMetadata] = []
        for path in sorted(rules_dir.glob("*.yml")):
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
            rules.append(RuleMetadata.model_validate(payload))
        if not rules:
            raise ValueError(f"No Sigma-style rules found in: {rules_dir}")
        return rules

    def evaluate(self, summary: FeatureSummary) -> RuleEvaluation:
        matches: list[RuleMatch] = []
        for rule in self.rules:
            evidence = self._evaluate_rule(rule, summary)
            if evidence is not None:
                matches.append(
                    RuleMatch(
                        rule_id=rule.id,
                        title=rule.title,
                        level=rule.level,
                        description=rule.description,
                        tags=rule.tags,
                        evidence=evidence,
                    )
                )

        highest_level = self._highest_level(matches)
        attack_tags = sorted({tag for match in matches for tag in match.tags if tag.startswith("attack.")})

        return RuleEvaluation(
            scenario_id=summary.scenario_id,
            hostname=summary.hostname,
            labels=list(summary.labels),
            triggered_rules=matches,
            matched_rule_count=len(matches),
            highest_level=highest_level,
            attack_tags=attack_tags,
        )

    def evaluate_from_path(self, input_path: str | Path) -> RuleEvaluation:
        payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
        summary = FeatureSummary.model_validate(payload)
        return self.evaluate(summary)

    def save_evaluation(self, evaluation: RuleEvaluation, output_path: str | Path, *, indent: int = 2) -> Path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(evaluation.model_dump(mode="json"), indent=indent), encoding="utf-8")
        return output

    def evaluate_and_save(self, input_path: str | Path, output_path: str | Path, *, indent: int = 2) -> RuleEvaluation:
        evaluation = self.evaluate_from_path(input_path)
        self.save_evaluation(evaluation, output_path, indent=indent)
        return evaluation

    def _evaluate_rule(self, rule: RuleMetadata, summary: FeatureSummary) -> dict[str, Any] | None:
        title = rule.title.lower()

        if title == "suspicious parent-child process chain":
            if summary.suspicious_parent_child:
                return {
                    "suspicious_parent_child_count": summary.suspicious_parent_child_count,
                    "unique_processes": summary.unique_processes,
                }
            return None

        if title == "suspicious command execution":
            if summary.suspicious_command:
                return {
                    "suspicious_command_count": summary.suspicious_command_count,
                    "command_exec_count": summary.command_exec_count,
                }
            return None

        if title == "suspicious shadow copy deletion":
            if summary.backup_delete_attempt:
                return {
                    "backup_delete_attempt_count": summary.backup_delete_attempt_count,
                    "event_type_counts": summary.event_type_counts,
                }
            return None

        if title == "mass file changes in short window":
            thresholds = rule.detection.get("feature", {})
            file_activity_threshold = int(thresholds.get("file_activity_threshold", 5))
            burst_file_threshold = int(thresholds.get("burst_file_threshold", 5))
            if summary.file_activity_count >= file_activity_threshold and summary.max_file_events_in_10s >= burst_file_threshold:
                return {
                    "file_activity_count": summary.file_activity_count,
                    "max_file_events_in_10s": summary.max_file_events_in_10s,
                    "unique_files_touched": summary.unique_files_touched,
                }
            return None

        if title == "bulk extension rename":
            thresholds = rule.detection.get("feature", {})
            extension_change_threshold = int(thresholds.get("extension_change_threshold", 3))
            if summary.extension_change_count >= extension_change_threshold:
                return {
                    "extension_change_count": summary.extension_change_count,
                    "file_rename_count": summary.file_rename_count,
                }
            return None

        if title == "suspicious outbound connection during file churn":
            thresholds = rule.detection.get("feature", {})
            network_connection_threshold = int(thresholds.get("network_connection_threshold", 1))
            file_activity_threshold = int(thresholds.get("file_activity_threshold", 3))
            if (
                summary.network_connection_count >= network_connection_threshold
                and summary.file_activity_count >= file_activity_threshold
            ):
                return {
                    "network_connection_count": summary.network_connection_count,
                    "file_activity_count": summary.file_activity_count,
                    "burst_activity_score": summary.burst_activity_score,
                }
            return None

        return None

    @staticmethod
    def _highest_level(matches: Iterable[RuleMatch]) -> str:
        highest = Severity.INFO.value
        highest_score = _LEVEL_ORDER[highest]
        for match in matches:
            level = match.level.lower()
            score = _LEVEL_ORDER.get(level, _LEVEL_ORDER[Severity.INFO.value])
            if score > highest_score:
                highest = level
                highest_score = score
        return highest
