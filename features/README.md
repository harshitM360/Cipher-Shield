# Phase 4 Feature Summaries

This folder stores derived behavioral summaries extracted from canonical event streams.

Each `*_features.json` file represents one scenario's event stream converted into:
- counts by event type
- file and directory touch metrics
- suspicious parent-child and command indicators
- simple burst metrics
- stage distribution

These summaries are the direct inputs for the Phase 5 rules engine.
