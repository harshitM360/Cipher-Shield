# Demo Guide

## 1. Install dependencies

```bash
pip install -r requirements.txt
```

## 2. Run the API

```bash
python run_api.py
```

The app starts on `http://127.0.0.1:8000`.

## 3. Check health

```bash
curl http://127.0.0.1:8000/health
```

Expected response:

```json
{"status": "ok"}
```

## 4. List available scenarios

```bash
curl http://127.0.0.1:8000/scenarios
```

## 5. Run a malicious scenario

```bash
curl -X POST http://127.0.0.1:8000/analyze/shadow_copy_delete_and_rename
```

This runs the complete pipeline and writes artifacts under `data/synthetic/`.

## 6. Fetch a saved SOC report

```bash
curl http://127.0.0.1:8000/reports/shadow_copy_delete_and_rename
```

## 7. Local script demo

```bash
python demo.py --scenario word_to_powershell
```

## Good demo scenarios

### Benign
- `normal_office_editing`
- `software_update_activity`
- `admin_bulk_rename`

### Malicious
- `word_to_powershell`
- `shadow_copy_delete_and_rename`
- `rapid_file_encryption_sim`

## What to show in an interview

- the scenario bundle format
- one generated event stream
- one feature summary
- triggered rules and rule evidence
- final SOC report with ATT&CK mapping and actions
