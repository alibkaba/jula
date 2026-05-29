# Jula Governor

The **Jula Governor** is the Registry and AI Generation engine of the Jula Controls ecosystem.

It houses the configuration components, data adapters, and executable rule criteria for the platform. It isolates high-level compliance checklists from raw execution code, delivering an automated, auditable security posture.

## Key Features

1. **Workspace Spec:** Acts as the central registry (`workspace.yaml`) declaring which providers and SaaS integrations are active.
2. **AI Translation:** Extracts engineering parameters from unstructured corporate GRC spreadsheets (`catalog.csv`).
3. **Policy Generation:** Autonomously writes and manages executable OPA Rego policies (`policies/rules/`).
4. **GitOps Self-Healing:** Powers the autonomous feedback loop that repairs `SCHEMA_DRIFT` anomalies detected by the `jula-evaluator`.

## Usage

For full ecosystem documentation, architecture diagrams, and licensing details, please refer to the [Root README](../README.md).
