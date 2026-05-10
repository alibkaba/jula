# Configs: Declarative Rule System

This directory contains the declarative configuration that drives the Jula Evidence Collector's policy evaluation engine. The Go code in `internal/` is stateless by design: all compliance logic, thresholds, and criteria mappings are defined here as data.

## File Reference

| File | Purpose |
| :--- | :--- |
| `soc2_mapping.json` | **Current (Production):** Maps infrastructure findings to specific AICPA Trust Services Criteria (e.g., CC6.1, CC7.2). This is the primary rule file that determines which `Finding` satisfies which SOC 2 control. |
| `iso27001_mapping.json`| **Next Up (Near-Term):** (In Development) Maps infrastructure findings to ISO 27001:2022 Annex A controls. This is the immediate roadmap priority for the Jula ecosystem. |
| `gcp_policy.json` | Defines environment-specific policy thresholds, such as the maximum allowed age for KMS key rotation (90 days) or the required backup retention period for Cloud SQL instances. |
| `exceptions.json` | Documents approved exceptions to policy rules. When a specific resource is intentionally non-compliant (e.g., a public-facing storage bucket for static assets), the exception is recorded here with a justification and expiration date. |

## Roadmap & Upcoming Rules

We ruthlessly prioritize mapping files that unblock enterprise revenue. The release schedule for new framework mappings is as follows:

1. **Immediate (v1.x):** `iso27001_mapping.json` (ISO 27001:2022 Annex A).
2. **Future (v2.x+):** NIST CSF, CIS Foundations Benchmarks, PCI-DSS, and HIPAA.

## Schemas

```
configs/
└── schemas/
    └── byoe_vulnerability_scan.json
```

The `schemas/` subdirectory contains JSON Schema (draft-07) definitions used by the `filedrop` provider to validate inbound BYOE evidence. When a client drops a vulnerability scan JSON file into the FileDrop bucket, Jula validates it against the corresponding schema before parsing and evaluation.

To add a new BYOE evidence type, create a new schema file in this directory and reference it from the filedrop provider's processing logic.

## Editing Guidelines

These files are the source of truth for the compliance engine. Changes to mapping rules or policy thresholds directly affect what Jula reports as PASS or FAIL.

- **Adding a new control mapping:** Add an entry to `soc2_mapping.json` with the finding ID, criteria reference, and evaluation logic.
- **Adjusting a threshold:** Modify the relevant value in `gcp_policy.json` (e.g., changing the rotation window from 90 to 60 days).
- **Approving an exception:** Add a new entry to `exceptions.json` with the resource identifier, justification, approver, and expiration timestamp.
