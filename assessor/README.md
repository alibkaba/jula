# Jula Assessor

The **Jula Assessor** is the Continuous Assurance Engine of the Jula Controls ecosystem.

It consumes raw ledger artifacts produced by the Collector, performs strict cryptographic gatekeeping, and executes dynamic OPA Rego policies to produce signed compliance verdicts.

## Key Features

1. **Gatekeeper Modules:** Validates ECDSA manifest signatures (Key A), verifies SHA-256 payload hashes, and checks provenance sidecars before any policy evaluation runs.
2. **Embedded OPA Engine:** Executes dynamic scoping and verification Rego rules supplied by the Governor.
3. **Schema Drift Detection:** Flags `SCHEMA_DRIFT` anomalies to trigger GitOps self-healing workflows.
4. **OSCAL Output:** Optionally produces NIST OSCAL 1.1.2 Assessment Results JSON via `--output-format oscal` (or `JULA_OUTPUT_FORMAT=oscal`).
5. **Signed Verdicts:** Every compliance verdict is ECDSA-signed (Key C) for tamper-evident audit trails.

## Usage

For full ecosystem documentation, architecture diagrams, and licensing details, see the [Root README](../README.md).