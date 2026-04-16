# Architecture

## Overview

The project is designed as a modular security analytics pipeline for ransomware-like activity.

```text
scenario bundle
  -> adapter
  -> canonical events
  -> feature extraction
  -> Sigma-style rules
  -> weighted scoring
  -> MITRE mapping
  -> SOC report generation
  -> FastAPI endpoints
```

## Components

### 1. Scenario bundles
Stored under `data/synthetic/scenarios/`.
They define synthetic benign and malicious timelines in a STIX-inspired format.

### 2. Synthetic adapter
File: `adapters/synthetic_adapter.py`

Responsibilities:
- load scenario bundles
- generate OCSF-aligned canonical events
- persist event streams to `data/synthetic/generated/`

### 3. Feature extractor
File: `features/extractor.py`

Responsibilities:
- compute event counts
- compute file churn and extension changes
- detect suspicious parent-child process chains
- detect rolling-window bursts

Outputs are stored in `data/synthetic/feature_summaries/`.

### 4. Rules engine
File: `detection/rules_engine.py`

Responsibilities:
- load Sigma-style YAML rules from `rules/`
- evaluate feature summaries
- produce rule-hit evidence and ATT&CK tags

Outputs are stored in `data/synthetic/rule_hits/`.

### 5. Risk scorer
File: `detection/scorer.py`

Responsibilities:
- combine rule hits and behavioral indicators
- produce rule score, behavior score, total score
- assign severity and confidence
- recommend response actions

Outputs are stored in `data/synthetic/risk_assessments/`.

### 6. MITRE mapper
File: `detection/mitre_mapper.py`

Responsibilities:
- map rule tags and behavior to ATT&CK techniques
- infer additional ATT&CK techniques when evidence is strong

Outputs are stored in `data/synthetic/mitre_mappings/`.

### 7. SOC report generator
File: `agent/summarizer.py`

Responsibilities:
- generate analyst-facing summaries
- surface severity, confidence, evidence, ATT&CK mapping, and actions

Outputs are stored in `data/synthetic/soc_reports/`.

### 8. API layer
Files: `api/app.py`, `api/routes.py`

Responsibilities:
- expose health checks
- list scenarios
- analyze scenarios end to end
- return saved SOC reports

Saved API payloads are stored in `data/synthetic/api_outputs/`.

## Design choices

### Why synthetic first?
Synthetic scenarios let the project stabilize the schema, pipeline, and detection logic before adding real telemetry adapters.

### Why not use an LLM for detection?
Detection is deliberately grounded in transparent rules and weighted scoring. Explainability sits on top of the detection core instead of replacing it.

### Future extension path
The normalized event layer is meant to support future adapters such as Sysmon and other endpoint or cloud telemetry sources.
