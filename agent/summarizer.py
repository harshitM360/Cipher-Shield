from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from detection.mitre_mapper import MitreMappingReport, MitreTechniqueMapping
from detection.rules_engine import RuleEvaluation
from detection.scorer import RiskAssessment
from features.extractor import FeatureSummary
from schemas.scenario import ScenarioBundle


class SocRuleSummary(BaseModel):
    """Analyst-facing summary of a triggered rule."""

    model_config = ConfigDict(extra="forbid")

    title: str
    level: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class SocTechniqueSummary(BaseModel):
    """Analyst-facing summary of an ATT&CK technique."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str
    technique_name: str
    tactics: list[str] = Field(default_factory=list)
    confidence: float
    rationale: str


class SocReport(BaseModel):
    """Phase 8 explainable SOC report for one scenario."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    scenario_name: str
    hostname: str
    labels: list[str] = Field(default_factory=list)
    executive_summary: str
    incident_classification: str
    severity: str
    confidence: float
    key_evidence: list[str] = Field(default_factory=list)
    triggered_rules: list[SocRuleSummary] = Field(default_factory=list)
    mitre_attack_mapping: list[SocTechniqueSummary] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    analyst_notes: list[str] = Field(default_factory=list)


class SocReportGenerator:
    """Generate human-readable SOC reports from prior pipeline outputs."""

    def generate(
        self,
        scenario: ScenarioBundle,
        summary: FeatureSummary,
        evaluation: RuleEvaluation,
        assessment: RiskAssessment,
        mapping: MitreMappingReport,
    ) -> SocReport:
        self._validate_alignment(scenario, summary, evaluation, assessment, mapping)

        severity = assessment.score_breakdown.severity
        confidence = assessment.score_breakdown.confidence
        classification = self._classify_incident(scenario, summary, assessment, mapping)

        key_evidence = self._build_key_evidence(summary, evaluation, assessment, mapping)
        triggered_rules = [
            SocRuleSummary(
                title=rule.title,
                level=rule.level,
                description=rule.description,
                evidence=rule.evidence,
            )
            for rule in evaluation.triggered_rules
        ]
        techniques = [self._map_technique(item) for item in mapping.mapped_techniques]

        executive_summary = self._build_executive_summary(
            scenario=scenario,
            classification=classification,
            severity=severity,
            confidence=confidence,
            key_evidence=key_evidence,
            mapping=mapping,
        )
        analyst_notes = self._build_analyst_notes(scenario, summary, assessment, mapping)

        return SocReport(
            scenario_id=scenario.id,
            scenario_name=scenario.name,
            hostname=scenario.host_profile.hostname,
            labels=list(scenario.labels),
            executive_summary=executive_summary,
            incident_classification=classification,
            severity=severity,
            confidence=confidence,
            key_evidence=key_evidence,
            triggered_rules=triggered_rules,
            mitre_attack_mapping=techniques,
            recommended_actions=list(assessment.recommended_actions),
            analyst_notes=analyst_notes,
        )

    def generate_from_paths(
        self,
        scenario_path: str | Path,
        feature_path: str | Path,
        rule_eval_path: str | Path,
        risk_assessment_path: str | Path,
        mitre_mapping_path: str | Path,
    ) -> SocReport:
        scenario = ScenarioBundle.model_validate_json(Path(scenario_path).read_text(encoding="utf-8"))
        summary = FeatureSummary.model_validate_json(Path(feature_path).read_text(encoding="utf-8"))
        evaluation = RuleEvaluation.model_validate_json(Path(rule_eval_path).read_text(encoding="utf-8"))
        assessment = RiskAssessment.model_validate_json(Path(risk_assessment_path).read_text(encoding="utf-8"))
        mapping = MitreMappingReport.model_validate_json(Path(mitre_mapping_path).read_text(encoding="utf-8"))
        return self.generate(scenario, summary, evaluation, assessment, mapping)

    def save_report(self, report: SocReport, output_path: str | Path, *, indent: int = 2) -> Path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report.model_dump(mode="json"), indent=indent), encoding="utf-8")
        return output

    def generate_and_save(
        self,
        scenario_path: str | Path,
        feature_path: str | Path,
        rule_eval_path: str | Path,
        risk_assessment_path: str | Path,
        mitre_mapping_path: str | Path,
        output_path: str | Path,
    ) -> SocReport:
        report = self.generate_from_paths(
            scenario_path,
            feature_path,
            rule_eval_path,
            risk_assessment_path,
            mitre_mapping_path,
        )
        self.save_report(report, output_path)
        return report

    @staticmethod
    def _validate_alignment(
        scenario: ScenarioBundle,
        summary: FeatureSummary,
        evaluation: RuleEvaluation,
        assessment: RiskAssessment,
        mapping: MitreMappingReport,
    ) -> None:
        scenario_id = scenario.id
        for other_id in [summary.scenario_id, evaluation.scenario_id, assessment.scenario_id, mapping.scenario_id]:
            if other_id != scenario_id:
                raise ValueError(
                    f"Scenario mismatch while generating SOC report. Expected {scenario_id!r}, got {other_id!r}."
                )

    @staticmethod
    def _map_technique(item: MitreTechniqueMapping) -> SocTechniqueSummary:
        return SocTechniqueSummary(
            technique_id=item.technique_id,
            technique_name=item.technique_name,
            tactics=list(item.tactics),
            confidence=item.confidence,
            rationale=item.rationale,
        )

    @staticmethod
    def _classify_incident(
        scenario: ScenarioBundle,
        summary: FeatureSummary,
        assessment: RiskAssessment,
        mapping: MitreMappingReport,
    ) -> str:
        severity = assessment.score_breakdown.severity
        labels = {label.lower() for label in scenario.labels}
        technique_ids = {item.technique_id for item in mapping.mapped_techniques}

        if severity == "info" and "benign" in labels:
            return "Benign administrative or user activity"
        if "T1486" in technique_ids:
            return "Likely ransomware impact activity"
        if severity in {"high", "critical"} and (summary.suspicious_parent_child or summary.suspicious_command):
            return "Suspicious pre-impact execution activity"
        if severity in {"medium", "high", "critical"}:
            return "Potential malicious activity requiring triage"
        return "Low-risk activity"

    @staticmethod
    def _build_key_evidence(
        summary: FeatureSummary,
        evaluation: RuleEvaluation,
        assessment: RiskAssessment,
        mapping: MitreMappingReport,
    ) -> list[str]:
        evidence: list[str] = []

        if evaluation.matched_rule_count == 0 and assessment.score_breakdown.severity == "info":
            evidence.append("No high-confidence malicious indicators were observed in the current scenario.")

        if summary.suspicious_parent_child_count:
            evidence.append(
                f"Observed {summary.suspicious_parent_child_count} suspicious parent-child process chain event(s)."
            )
        if summary.suspicious_command_count:
            evidence.append(
                f"Observed {summary.suspicious_command_count} suspicious command execution indicator(s)."
            )
        if summary.backup_delete_attempt_count:
            evidence.append(
                f"Detected {summary.backup_delete_attempt_count} recovery or shadow-copy deletion attempt(s)."
            )
        if summary.file_activity_count:
            evidence.append(
                f"File activity reached {summary.file_activity_count} total event(s), including {summary.file_rename_count} rename event(s)."
            )
        if summary.extension_change_count:
            evidence.append(
                f"Detected {summary.extension_change_count} file extension change event(s), consistent with ransomware impact behavior."
            )
        if summary.network_connection_count:
            evidence.append(
                f"Observed {summary.network_connection_count} network connection event(s) during the scenario."
            )
        if evaluation.matched_rule_count:
            evidence.append(
                f"Triggered {evaluation.matched_rule_count} detection rule(s), highest rule severity: {evaluation.highest_level}."
            )
        if mapping.mapped_techniques:
            technique_ids = ", ".join(item.technique_id for item in mapping.mapped_techniques)
            evidence.append(f"Mapped to ATT&CK technique(s): {technique_ids}.")

        if not evidence:
            evidence.append("No high-confidence malicious indicators were observed in the current scenario.")

        return evidence

    @staticmethod
    def _build_executive_summary(
        *,
        scenario: ScenarioBundle,
        classification: str,
        severity: str,
        confidence: float,
        key_evidence: list[str],
        mapping: MitreMappingReport,
    ) -> str:
        technique_part = ""
        if mapping.mapped_techniques:
            technique_part = (
                " ATT&CK coverage includes "
                + ", ".join(item.technique_id for item in mapping.mapped_techniques)
                + "."
            )

        top_evidence = key_evidence[0]
        return (
            f"Scenario '{scenario.name}' is classified as {classification.lower()} with {severity} severity "
            f"at confidence {confidence:.3f}. {top_evidence}{technique_part}"
        )

    @staticmethod
    def _build_analyst_notes(
        scenario: ScenarioBundle,
        summary: FeatureSummary,
        assessment: RiskAssessment,
        mapping: MitreMappingReport,
    ) -> list[str]:
        notes = [f"Objective: {scenario.objective}"]
        notes.append(
            f"Host profile: {scenario.host_profile.hostname} / {scenario.host_profile.os} / {scenario.host_profile.department}."
        )

        dominant_stage = "unknown"
        if summary.stage_counts:
            dominant_stage = max(summary.stage_counts.items(), key=lambda item: item[1])[0]
        notes.append(f"Dominant activity stage: {dominant_stage}.")
        notes.append(
            f"Scoring breakdown: rule={assessment.score_breakdown.rule_score}, behavior={assessment.score_breakdown.behavior_score}, total={assessment.score_breakdown.total_score}."
        )
        if mapping.mapped_techniques:
            notes.append(
                "Most relevant ATT&CK techniques: "
                + ", ".join(item.technique_id for item in mapping.mapped_techniques)
                + "."
            )
        else:
            notes.append("No ATT&CK techniques were mapped with high confidence.")
        return notes


def generate_all_soc_reports(
    scenario_dir: str | Path,
    feature_dir: str | Path,
    rule_hits_dir: str | Path,
    risk_assessments_dir: str | Path,
    mitre_mappings_dir: str | Path,
    output_dir: str | Path,
) -> list[Path]:
    """Generate one SOC report for each saved scenario pipeline output."""

    generator = SocReportGenerator()
    scenario_root = Path(scenario_dir)
    feature_root = Path(feature_dir)
    rule_root = Path(rule_hits_dir)
    risk_root = Path(risk_assessments_dir)
    mitre_root = Path(mitre_mappings_dir)
    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)

    saved_paths: list[Path] = []
    for scenario_path in sorted(scenario_root.glob("*.json")):
        scenario_stub = scenario_path.stem
        feature_path = feature_root / f"{scenario_stub}_features.json"
        rule_path = rule_root / f"{scenario_stub}_rule_hits.json"
        risk_path = risk_root / f"{scenario_stub}_risk_assessment.json"
        mitre_path = mitre_root / f"{scenario_stub}_mitre_mapping.json"
        output_path = output_root / f"{scenario_stub}_soc_report.json"

        missing = [
            str(path) for path in [feature_path, rule_path, risk_path, mitre_path] if not path.exists()
        ]
        if missing:
            raise FileNotFoundError(
                f"Cannot generate SOC report for {scenario_stub}; missing required file(s): {missing}"
            )

        generator.generate_and_save(
            scenario_path,
            feature_path,
            rule_path,
            risk_path,
            mitre_path,
            output_path,
        )
        saved_paths.append(output_path)
    return saved_paths
