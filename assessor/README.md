# Jula Assessor

The **Jula Assessor** is the Continuous Assurance Engine of the Jula Controls ecosystem.

It assesses compliance by consuming the raw ledger artifacts produced by the `jula-collector`. The Assessor runs a stateless Go engine that performs strict cryptographic gatekeeping before executing dynamic Open Policy Agent (OPA) rules.

## Key Features

1. **Gatekeeper Modules:**
   - **Signature Verification:** Validates the ECDSA signatures on the incoming manifest using the `JULA_PUBLIC_KEY`.
   - **Integrity Check:** Compares the SHA-256 hashes of the actual payloads against the values logged in the signed manifest.
   - **Provenance Verification:** Verifies the sidecar payloads to guarantee evidence authenticity.
2. **Embedded OPA Engine:** Executes dynamic scoping and verification Rego rules (supplied by `jula-governor`) against the authenticated payloads.
3. **Schema Drift Detection:** Flags `SCHEMA_DRIFT` anomalies to trigger the Jula GitOps self-healing workflows.
4. **OSCAL Output:** Optionally produces a NIST OSCAL 1.1.2 Assessment Results JSON document alongside the standard findings ledger.

## OSCAL Assessment Results

When the `--output-format oscal` flag is set (or `JULA_OUTPUT_FORMAT=oscal` environment variable), the Assessor maps its control findings to a standards-compliant OSCAL Assessment Results document and writes `assessment-results.json` to the evidence bucket.

| Environment Variable | Description | Default |
| :--- | :--- | :--- |
| `JULA_OUTPUT_FORMAT` | Set to `oscal` to enable OSCAL AR output | (disabled) |
| `JULA_ORGANIZATION` | Organization name for OSCAL metadata party | `Jula Controls` |
| `JULA_FRAMEWORK` | Compliance framework name for OSCAL properties | `SCF` |

The OSCAL document includes:

- UUID-stamped metadata with organization and framework properties
- Each control finding mapped to an OSCAL `finding` with `satisfied` or `not-satisfied` status
- Signed verdict properties embedded when Key C is configured

## Usage

For full ecosystem documentation, architecture diagrams, and licensing details, please refer to the [Root README](../README.md).