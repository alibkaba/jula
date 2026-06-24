# Evidence Schema Catalog

This directory contains JSON Schema definitions for all evidence types consumed by the Jula Assessor. Any tool producing evidence for Jula must conform to these schemas.

---

## Schemas

| Schema | Description | Required By |
|:-------|:-----------|:------------|
| [evidence.schema.json](evidence.schema.json) | Top-level evidence wrapper | `jula-sign-evidence` validation gate |
| [finding.schema.json](finding.schema.json) | Finding object within evidence | Referenced by evidence schema |

---

## Evidence Structure

Every evidence file is a JSON object with the following shape:

```json
{
  "evidence_id": "EVID-BCM-16",
  "control_id": "BCD-11.4",
  "source_id": "my-gcp-project-123",
  "payload_hash": "a1b2c3d4...64 hex chars",
  "finding": {
    "evidence_id": "EVID-BCM-16",
    "control_id": "BCD-11.4",
    "source_id": "my-gcp-project-123",
    "provider": "steampipe",
    "raw_data": { ... },
    "timestamp": "2026-06-24T19:00:00Z",
    "run_id": "run-20260624-001"
  }
}
```

### Field Reference

#### Top-Level Fields

| Field | Type | Required | Description |
|:------|:-----|:---------|:-----------|
| `evidence_id` | string | Yes | Evidence Request List identifier (e.g., `EVID-BCM-16`). Primary routing key. |
| `control_id` | string | Yes | Generic control identifier mapped to OSCAL (e.g., `BCD-11.4`, `ac-1`). |
| `source_id` | string | Yes | Resource source (GCP project ID, AWS account ID, etc.). |
| `payload_hash` | string | Yes | SHA-256 hex hash of `finding.raw_data`. Must be 64 lowercase hex characters. |
| `finding` | object | Yes | The extraction data and metadata. See below. |

#### Finding Fields

| Field | Type | Required | Description |
|:------|:-----|:---------|:-----------|
| `evidence_id` | string | Yes | Same as top-level `evidence_id`. |
| `control_id` | string | Yes | Same as top-level `control_id`. |
| `source_id` | string | Yes | Same as top-level `source_id`. |
| `provider` | string | Yes | Tool that produced the extraction (e.g., `gcp_cai`, `steampipe`, `cloudquery`, `filedrop`). |
| `raw_data` | any | Yes | Raw extraction payload. JSON object/array from API responses, or raw content for file drops. |
| `timestamp` | string | Yes | ISO 8601 / RFC 3339 timestamp of extraction (UTC). |
| `run_id` | string | Yes | Unique identifier linking all evidence from a single collection run. |

---

## Validation

`jula-sign-evidence` validates every `.json` file against these schemas before signing. To skip validation (e.g., for non-evidence files), use:

```bash
jula-sign-evidence --input ./evidence/ --output gs://bucket --no-schema
```

### Validation Behavior

- All `.json` files in the input directory are validated
- Non-JSON files (CSV, PDF, etc.) are signed without validation
- Validation checks: required fields, type correctness, `payload_hash` format
- If any file fails validation, signing is aborted for the entire batch

---

## Producing Evidence

Any tool can produce evidence for Jula. Here's a minimal example:

```bash
# 1. Collect raw data with your preferred tool
steampipe query "select * from gcp_storage_bucket" --output json > raw_buckets.json

# 2. Wrap in Jula evidence format
cat > evidence/s3_buckets.json << 'EOF'
{
  "evidence_id": "EVID-STORAGE-01",
  "control_id": "sc-28",
  "source_id": "my-project-123",
  "payload_hash": "$(sha256sum raw_buckets.json | cut -d' ' -f1)",
  "finding": {
    "evidence_id": "EVID-STORAGE-01",
    "control_id": "sc-28",
    "source_id": "my-project-123",
    "provider": "steampipe",
    "raw_data": $(cat raw_buckets.json),
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "run_id": "manual-2026-06-24"
  }
}
EOF

# 3. Sign with Jula
jula-sign-evidence --input ./evidence/ --output gs://jula-ledger
```
