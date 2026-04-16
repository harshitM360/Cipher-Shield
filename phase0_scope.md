# Phase 0 - Scope Freeze

## Project Title
AI-Powered Explainable SOC Copilot for Ransomware Detection

## Problem Statement
Organizations receive too many raw security events, and traditional detection systems often produce alerts without enough context or explanation. Ransomware attacks are especially dangerous because they can rapidly encrypt files, disrupt recovery mechanisms, and cause operational downtime. The goal of this project is to build an AI-assisted SOC copilot that detects ransomware-like behavior from endpoint activity, explains why the behavior is suspicious, maps it to known attack techniques, and recommends response actions.

## One-Line Goal
Build a system that detects ransomware-like endpoint behavior and produces analyst-style explainable incident reports with action recommendations.

## Current Scope (V1)
### In Scope
- Windows endpoint-focused prototype
- Synthetic scenario-based input
- OCSF-aligned canonical events
- STIX-inspired scenario bundles
- Sigma-style detection rules
- Rule-based detection
- Weighted risk scoring
- MITRE ATT&CK mapping
- Explainable SOC-style report generation
- FastAPI output layer
- Offline/local execution

### Out of Scope
- Real-time enterprise deployment
- Full SIEM platform
- Detection of all malware families
- Static malware binary analysis
- Deep-learning malware classifier
- Linux support in V1
- Cloud workload detection in V1
- Autonomous production remediation
- Live LLM dependency for core detection
- Real EDR isolation/integration in V1

## Detection Focus
The system focuses on ransomware-related behavioral signals, especially:
- Suspicious process chains
- Shadow copy / recovery deletion attempts
- Mass file modifications
- Mass file renames
- Rapid extension changes
- Optional suspicious outbound contact later

## AI Role
### AI Is Used For
- Explaining incident context
- Summarizing evidence
- Formatting analyst-readable reports
- Recommending response steps
- Assisting triage

### AI Is Not Used For
- Acting as the only detection engine
- Replacing deterministic rules
- Serving as a black-box malware classifier

## Input and Output
### Input
Synthetic security scenarios converted into canonical endpoint events.

### Output
A structured incident report containing:
- Severity
- Evidence
- Triggered rules
- ATT&CK mapping
- Recommended actions
- Confidence/risk score

## Standards Freeze
- Canonical events: OCSF-aligned JSON
- Scenarios: STIX-inspired JSON bundle
- Detection rules: Sigma-style YAML

## Primary User
- SOC analyst
- Security student or research demo user
- Security engineer evaluating suspicious behavior

## Success Criteria for V1
The project is successful if it can:
1. Take a benign or ransomware-like synthetic scenario
2. Convert it into normalized event records
3. Extract meaningful behavioral features
4. Trigger relevant detection rules
5. Assign sensible severity
6. Map behavior to MITRE ATT&CK techniques
7. Generate a readable SOC-style report

## Failure Conditions
The project is failing if it becomes:
- Too broad to finish
- Only a dashboard with no detection logic
- Only a rule engine with no explainability
- Only an LLM wrapper with no real detection
- Too source-specific to extend to real logs later

## Angle Freeze
### Present Focus
Angle 2: Explainable SOC Copilot

### Future Extension
Angle 3: Cross-platform and cloud correlation

## Final Frozen Definition
We are building an offline, Windows endpoint-focused, AI-assisted ransomware detection prototype that uses synthetic but production-style event data, applies rule-based and risk-scoring analysis, maps detections to MITRE ATT&CK, and generates explainable SOC-style incident reports. The system is designed to be extensible to real telemetry sources later through normalized event schemas and source adapters.
