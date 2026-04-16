# Cipher-Shield

An offline, Windows endpoint-focused prototype that detects ransomware-like behavior from synthetic but production-style telemetry, maps the activity to MITRE ATT&CK, and generates analyst-style SOC reports.

## What this project does

This project takes a synthetic scenario bundle and runs it through a full detection pipeline:

1. Scenario bundle ingestion
2. OCSF-aligned canonical event generation
3. Behavioral feature extraction
4. Sigma-style rule evaluation
5. Weighted risk scoring
6. MITRE ATT&CK mapping
7. SOC-style report generation
8. FastAPI exposure

The current version is intentionally focused on explainability and pipeline design rather than real-time enterprise deployment.

## Current scope

### In scope
- Windows endpoint-focused ransomware prototype
- STIX-inspired scenario bundles
- OCSF-aligned canonical event schema
- Sigma-style detection rules
- Rule-based ransomware behavior detection
- Weighted risk scoring
- MITRE ATT&CK mapping
- SOC-style report generation
- FastAPI endpoints for analysis and report retrieval

### Out of scope
- Real-time production deployment
- Full SIEM replacement
- Linux and cloud coverage in V1
- Static malware analysis
- Autonomous remediation
- End-to-end LLM detection

## Architecture

```text
scenario bundle
  -> synthetic adapter
  -> canonical events
  -> feature extractor
  -> rules engine
  -> risk scorer
  -> MITRE mapper
  -> SOC summarizer
  -> FastAPI layer
```

More detail is in [`docs/architecture.md`](docs/architecture.md).

## Project structure

```text
ransomware_copilot/
├── adapters/
├── agent/
├── api/
├── data/
│   └── synthetic/
│       ├── scenarios/
│       ├── generated/
│       ├── feature_summaries/
│       ├── rule_hits/
│       ├── risk_assessments/
│       ├── mitre_mappings/
│       ├── soc_reports/
│       └── api_outputs/
├── detection/
├── docs/
├── features/
├── rules/
├── schemas/
└── tests/
```

## Requirements

- Python 3.11+
- FastAPI
- Uvicorn
- Pydantic
- PyYAML
- pytest

Install with:

```bash
pip install -r requirements.txt
```

## Running the API

From the project root:

```bash
python run_api.py
```

Or directly:

```bash
uvicorn api.app:app --reload
```

## Demo run

Run one full scenario through the pipeline:

```bash
python demo.py --scenario shadow_copy_delete_and_rename
```

This prints a compact summary and saves the pipeline outputs under `data/synthetic/`.

## Example API usage

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/scenarios
curl -X POST http://127.0.0.1:8000/analyze/word_to_powershell
curl http://127.0.0.1:8000/reports/shadow_copy_delete_and_rename
```

More examples are in [`docs/api_usage.md`](docs/api_usage.md).

## Current pipeline outputs

For each scenario, the project persists:
- canonical events
- feature summaries
- rule hits
- risk assessments
- MITRE mappings
- SOC reports
- API outputs

## Why this project is strong

- clear separation between detection and explanation
- explainable scoring instead of black-box classification
- future-ready normalized schema design
- clean handoff path from synthetic data to real telemetry adapters later

## Future work

- add real Sysmon parser support
- add anomaly scoring on top of weighted rules
- extend to Linux, containers, and cloud telemetry
- add CLI and dashboard views
- package with Docker
