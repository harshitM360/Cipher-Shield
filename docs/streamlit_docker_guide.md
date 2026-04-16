# Streamlit Docker Guide

## Build the image

```bash
docker build -t ransomware-copilot-streamlit .
```

## Run the container

```bash
docker run --rm -p 8501:8501 ransomware-copilot-streamlit
```

Then open:

```text
http://localhost:8501
```

## Run with Docker Compose

```bash
docker compose up --build
```

## What the app shows

- scenario picker
- one-click pipeline execution
- severity, confidence, score, and rule count
- evidence, ATT&CK mapping, response actions, and raw JSON output

## Notes

- The app runs the existing pipeline through `api.routes.run_pipeline`.
- Generated files are written back into `data/synthetic/` when persistence is enabled in the UI.
- The Docker image is designed for the Streamlit demo layer, not the FastAPI service.
