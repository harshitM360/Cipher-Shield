from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from detection.rules_engine import RuleEvaluation
from detection.scorer import RiskAssessment
from schemas import Severity


_TECHNIQUE_CATALOG: dict[str, dict[str, Any]] = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactics": ["execution"],
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactics": ["execution"],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactics": ["command-and-control"],
    },
    "T1204": {
        "name": "User Execution",
        "tactics": ["execution"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactics": ["impact"],
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactics": ["impact"],
    },
}

_TAG_TO_TECHNIQUE_ID: dict[str, str] = {
    "attack.t1059": "T1059",
    "attack.t1059.001": "T1059.001",
    "attack.t1105": "T1105",
    "attack.t1204": "T1204",
    "attack.t1486": "T1486",
    "attack.t1490": "T1490",
}


class MitreTechniqueMapping(BaseModel):
    """One ATT&CK technique mapped to a scenario with rationale."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str
    technique_name: str
    tactics: list[str] = Field(default_factory=list)
    source: str
    confidence: float
    rationale: str


class MitreMappingReport(BaseModel):
    """Phase 7 ATT&CK mapping output for one scenario."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    hostname: str
    labels: list[str] = Field(default_factory=list)
    severity: str
    matched_rule_count: int
    source_attack_tags: list[str] = Field(default_factory=list)
    mapped_techniques: list[MitreTechniqueMapping] = Field(default_factory=list)
    unmapped_attack_tags: list[str] = Field(default_factory=list)
    summary: str


class MitreMapper:
    """Map rule outputs and risk assessments to ATT&CK techniques."""

    def map(self, evaluation: RuleEvaluation, assessment: RiskAssessment) -> MitreMappingReport:
        if evaluation.scenario_id != assessment.scenario_id:
            raise ValueError(
                "Rule evaluation and risk assessment must belong to the same scenario. "
                f"Got {evaluation.scenario_id!r} and {assessment.scenario_id!r}."
            )

        mapped: dict[str, MitreTechniqueMapping] = {}
        unmapped_tags: list[str] = []

        for tag in evaluation.attack_tags:
            technique_id = _TAG_TO_TECHNIQUE_ID.get(tag.lower())
            if technique_id is None:
                unmapped_tags.append(tag)
                continue
            mapped[technique_id] = self._build_mapping(
                technique_id,
                source="rule_tag",
                confidence=0.95,
                rationale=f"Mapped directly from triggered rule tag {tag}.",
            )

        factor_names = {
            factor.get("name", "")
            for factor in assessment.score_breakdown.contributing_factors
        }
        rule_names = {
            factor.get("name", "")
            for factor in assessment.score_breakdown.contributing_factors
            if factor.get("type") == "rule"
        }

        self._add_if_missing(
            mapped,
            "T1490",
            should_add=(
                "Suspicious Shadow Copy Deletion" in rule_names
                or "Backup deletion attempt present" in factor_names
            ),
            confidence=0.92,
            rationale="Inferred from recovery sabotage behavior such as shadow copy deletion.",
        )
        self._add_if_missing(
            mapped,
            "T1486",
            should_add=(
                "Bulk Extension Rename" in rule_names
                or "Mass File Changes in Short Window" in rule_names
                or "Multiple extension changes" in factor_names
                or "High file activity burst" in factor_names
            ) and assessment.score_breakdown.severity in {Severity.HIGH.value, Severity.CRITICAL.value},
            confidence=0.88,
            rationale="Inferred from ransomware-like file churn or extension changes consistent with encryption impact.",
        )
        self._add_if_missing(
            mapped,
            "T1059.001",
            should_add=(
                "Suspicious Command Execution" in rule_names
                or "Suspicious command usage" in factor_names
                or "Office application spawned suspicious scripting activity" in factor_names
            ) and assessment.score_breakdown.severity in {Severity.HIGH.value, Severity.CRITICAL.value},
            confidence=0.85,
            rationale="Inferred from suspicious PowerShell-style command execution evidence.",
        )
        self._add_if_missing(
            mapped,
            "T1204",
            should_add=(
                "Suspicious Parent-Child Process Chain" in rule_names
                or "Office application spawned suspicious scripting activity" in factor_names
            ) and assessment.score_breakdown.severity in {Severity.HIGH.value, Severity.CRITICAL.value},
            confidence=0.8,
            rationale="Inferred from suspicious user-launched office application to scripting activity chain.",
        )
        self._add_if_missing(
            mapped,
            "T1105",
            should_add=(
                "Suspicious Outbound Connection During File Churn" in rule_names
                or "Network activity during file churn" in factor_names
            ) and assessment.score_breakdown.severity in {Severity.HIGH.value, Severity.CRITICAL.value},
            confidence=0.82,
            rationale="Inferred from outbound network activity correlated with suspicious file churn.",
        )

        ordered_techniques = sorted(mapped.values(), key=lambda item: item.technique_id)
        summary = self._build_summary(assessment, ordered_techniques)

        return MitreMappingReport(
            scenario_id=assessment.scenario_id,
            hostname=assessment.hostname,
            labels=list(assessment.labels),
            severity=assessment.score_breakdown.severity,
            matched_rule_count=assessment.matched_rule_count,
            source_attack_tags=list(evaluation.attack_tags),
            mapped_techniques=ordered_techniques,
            unmapped_attack_tags=unmapped_tags,
            summary=summary,
        )

    def map_from_paths(self, rule_eval_path: str | Path, risk_assessment_path: str | Path) -> MitreMappingReport:
        evaluation = RuleEvaluation.model_validate_json(Path(rule_eval_path).read_text(encoding="utf-8"))
        assessment = RiskAssessment.model_validate_json(Path(risk_assessment_path).read_text(encoding="utf-8"))
        return self.map(evaluation, assessment)

    def save_mapping(self, report: MitreMappingReport, output_path: str | Path, *, indent: int = 2) -> Path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report.model_dump(mode="json"), indent=indent), encoding="utf-8")
        return output

    def map_and_save(self, rule_eval_path: str | Path, risk_assessment_path: str | Path, output_path: str | Path) -> MitreMappingReport:
        report = self.map_from_paths(rule_eval_path, risk_assessment_path)
        self.save_mapping(report, output_path)
        return report

    @staticmethod
    def _build_mapping(technique_id: str, *, source: str, confidence: float, rationale: str) -> MitreTechniqueMapping:
        metadata = _TECHNIQUE_CATALOG[technique_id]
        return MitreTechniqueMapping(
            technique_id=technique_id,
            technique_name=metadata["name"],
            tactics=list(metadata["tactics"]),
            source=source,
            confidence=round(confidence, 3),
            rationale=rationale,
        )

    def _add_if_missing(
        self,
        mapped: dict[str, MitreTechniqueMapping],
        technique_id: str,
        *,
        should_add: bool,
        confidence: float,
        rationale: str,
    ) -> None:
        if not should_add or technique_id in mapped:
            return
        mapped[technique_id] = self._build_mapping(
            technique_id,
            source="behavior_inference",
            confidence=confidence,
            rationale=rationale,
        )

    @staticmethod
    def _build_summary(assessment: RiskAssessment, techniques: list[MitreTechniqueMapping]) -> str:
        if not techniques:
            return (
                f"No ATT&CK techniques were mapped for {assessment.scenario_id}; "
                "current evidence does not indicate a high-confidence adversarial technique."
            )

        joined_ids = ", ".join(item.technique_id for item in techniques)
        return (
            f"Mapped {len(techniques)} ATT&CK technique(s) for {assessment.scenario_id} "
            f"at severity {assessment.score_breakdown.severity}: {joined_ids}."
        )


def map_all_risk_assessments(
    rule_hits_dir: str | Path,
    risk_assessments_dir: str | Path,
    output_dir: str | Path,
) -> list[Path]:
    """Map every saved risk assessment to ATT&CK using its matching rule-hit file."""

    mapper = MitreMapper()
    rule_root = Path(rule_hits_dir)
    risk_root = Path(risk_assessments_dir)
    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)

    saved_paths: list[Path] = []
    for assessment_path in sorted(risk_root.glob("*_risk_assessment.json")):
        scenario_stub = assessment_path.name.replace("_risk_assessment.json", "")
        rule_eval_path = rule_root / f"{scenario_stub}_rule_hits.json"
        if not rule_eval_path.exists():
            raise FileNotFoundError(f"Missing rule evaluation for risk assessment: {rule_eval_path}")
        output_path = output_root / f"{scenario_stub}_mitre_mapping.json"
        mapper.map_and_save(rule_eval_path, assessment_path, output_path)
        saved_paths.append(output_path)
    return saved_paths
