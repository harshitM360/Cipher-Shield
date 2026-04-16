# API Usage

Base URL when running locally:

```text
http://127.0.0.1:8000
```

## GET /health

### Request

```bash
curl http://127.0.0.1:8000/health
```

### Response

```json
{"status": "ok"}
```

## GET /scenarios

### Request

```bash
curl http://127.0.0.1:8000/scenarios
```

### Response shape

```json
{
  "scenarios": [
    "admin_bulk_rename",
    "normal_office_editing",
    "rapid_file_encryption_sim"
  ]
}
```

## POST /analyze/{scenario_name}

### Request

```bash
curl -X POST http://127.0.0.1:8000/analyze/word_to_powershell
```

### Response contains
- `scenario_name`
- `scenario_id`
- `feature_summary`
- `rule_evaluation`
- `risk_assessment`
- `mitre_mapping`
- `soc_report`

## GET /reports/{scenario_name}

### Request

```bash
curl http://127.0.0.1:8000/reports/shadow_copy_delete_and_rename
```

### Response contains
A saved SOC report with:
- executive summary
- incident classification
- severity
- confidence
- key evidence
- triggered rules
- MITRE ATT&CK mapping
- recommended actions
- analyst notes

## Error behavior

If an unknown scenario name is used, the API returns HTTP 404.
