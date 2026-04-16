from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException

from adapters.synthetic_adapter import SyntheticScenarioAdapter
from agent.summarizer import SocReportGenerator
from detection.mitre_mapper import MitreMapper
from detection.rules_engine import RulesEngine
from detection.scorer import RiskScorer
from features.extractor import FeatureExtractor

router = APIRouter()

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_ROOT = PROJECT_ROOT / "data" / "synthetic"
SCENARIOS_DIR = DATA_ROOT / "scenarios"
GENERATED_DIR = DATA_ROOT / "generated"
FEATURES_DIR = DATA_ROOT / "feature_summaries"
RULE_HITS_DIR = DATA_ROOT / "rule_hits"
RISK_DIR = DATA_ROOT / "risk_assessments"
MITRE_DIR = DATA_ROOT / "mitre_mappings"
SOC_DIR = DATA_ROOT / "soc_reports"
API_OUTPUTS_DIR = DATA_ROOT / "api_outputs"
RULES_DIR = PROJECT_ROOT / "rules"

_adapter = SyntheticScenarioAdapter()
_extractor = FeatureExtractor()
_rules_engine = RulesEngine(RULES_DIR)
_scorer = RiskScorer()
_mitre_mapper = MitreMapper()
_soc_generator = SocReportGenerator()


class PipelinePaths(dict):
    pass


def _safe_name_to_path(scenario_name: str) -> Path:
    path = SCENARIOS_DIR / f"{scenario_name}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Unknown scenario: {scenario_name}")
    return path


def _pipeline_paths(scenario_name: str) -> dict[str, Path]:
    return {
        "scenario": SCENARIOS_DIR / f"{scenario_name}.json",
        "events": GENERATED_DIR / f"{scenario_name}_events.json",
        "features": FEATURES_DIR / f"{scenario_name}_features.json",
        "rule_hits": RULE_HITS_DIR / f"{scenario_name}_rule_hits.json",
        "risk_assessment": RISK_DIR / f"{scenario_name}_risk_assessment.json",
        "mitre_mapping": MITRE_DIR / f"{scenario_name}_mitre_mapping.json",
        "soc_report": SOC_DIR / f"{scenario_name}_soc_report.json",
        "api_output": API_OUTPUTS_DIR / f"{scenario_name}_api_output.json",
    }


def _list_scenario_names() -> list[str]:
    return sorted(path.stem for path in SCENARIOS_DIR.glob('*.json'))


def run_pipeline(scenario_name: str, *, persist: bool = True) -> dict[str, Any]:
    scenario_path = _safe_name_to_path(scenario_name)
    paths = _pipeline_paths(scenario_name)

    bundle = _adapter.load_bundle(scenario_path)
    events = _adapter.generate_events(bundle)
    if persist:
        _adapter.save_generated_events(bundle, paths['events'])

    feature_summary = _extractor.extract(events)
    if persist:
        _extractor.save_summary(feature_summary, paths['features'])

    rule_evaluation = _rules_engine.evaluate(feature_summary)
    if persist:
        _rules_engine.save_evaluation(rule_evaluation, paths['rule_hits'])

    risk_assessment = _scorer.score(feature_summary, rule_evaluation)
    if persist:
        _scorer.save_assessment(risk_assessment, paths['risk_assessment'])

    mitre_mapping = _mitre_mapper.map(rule_evaluation, risk_assessment)
    if persist:
        _mitre_mapper.save_mapping(mitre_mapping, paths['mitre_mapping'])

    soc_report = _soc_generator.generate(bundle, feature_summary, rule_evaluation, risk_assessment, mitre_mapping)
    if persist:
        _soc_generator.save_report(soc_report, paths['soc_report'])

    payload: dict[str, Any] = {
        "scenario_name": scenario_name,
        "scenario_id": bundle.id,
        "feature_summary": feature_summary.model_dump(mode='json'),
        "rule_evaluation": rule_evaluation.model_dump(mode='json'),
        "risk_assessment": risk_assessment.model_dump(mode='json'),
        "mitre_mapping": mitre_mapping.model_dump(mode='json'),
        "soc_report": soc_report.model_dump(mode='json'),
    }

    if persist:
        API_OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
        paths['api_output'].write_text(json.dumps(payload, indent=2), encoding='utf-8')

    return payload


@router.get('/health')
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get('/scenarios')
def list_scenarios() -> dict[str, list[str]]:
    return {"scenarios": _list_scenario_names()}


@router.post('/analyze/{scenario_name}')
def analyze_scenario(scenario_name: str) -> dict[str, Any]:
    return run_pipeline(scenario_name, persist=True)


@router.get('/reports/{scenario_name}')
def get_saved_report(scenario_name: str) -> dict[str, Any]:
    _safe_name_to_path(scenario_name)
    report_path = _pipeline_paths(scenario_name)['soc_report']
    if not report_path.exists():
        run_pipeline(scenario_name, persist=True)
    return json.loads(report_path.read_text(encoding='utf-8'))
