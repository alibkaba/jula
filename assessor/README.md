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

## Usage

For full ecosystem documentation, architecture diagrams, and licensing details, please refer to the [Root README](../README.md).