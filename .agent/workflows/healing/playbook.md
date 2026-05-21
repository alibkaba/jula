# Agent Context Playbook: Autonomous Drift Repair

This playbook defines instructions, rules, and constraints for the autonomous worker agent when diagnosing schema drift and regenerating OPA Rego normalization files.

## 1. Context Analysis & Payload Parsing

When a drift event is triggered, you will be provided with:
* The **old JSON fixture file** representing the historically valid API response.
* The **drifting raw payload** extracted from the active cloud provider endpoints.
* The **target Rego normalization file** that must be rewritten (e.g., `policies/normalization/gcp/database.rego`).

You must compare the old fixture against the new drifting raw payload to identify mutated field names, updated structure hierarchies, or newly introduced labels.

## 2. Target Normalization Schemas

You must map the incoming raw cloud payloads to the following standardized schemas:

### DatabaseSchema
All properties must be evaluated using lowercase snake_case keys:
* `encrypted_at_rest` (boolean): Indicates whether data at rest is encrypted.
* `require_tls` (boolean): Indicates whether connection configuration mandates TLS/SSL.
* `publicly_accessible` (boolean): Indicates if the instance is exposed to public IPv4 access.
* `environment` (string): The environment classification (e.g. `production`, `development`).
* `backups_enabled` (boolean): Indicates if database backup configurations are active.

### StorageSchema
All properties must be mapped as follows:
* `uniform_bucket_level_access` (boolean): Indicates if IAM uniform bucket-level access is enabled.
* `public_access_prevention` (string): The status of public access prevention (e.g., `enforced`, `inherited`).
* `data_class` (string): Data classification classification (e.g. `sensitive`, `public`).
* `privacy` (string): Privacy standards applied to the bucket (e.g. `gdpr`).
* `has_cmek` (boolean): Indicates whether a Customer-Managed Encryption Key is set.
* `has_delete_lifecycle` (boolean): Indicates if an active Delete lifecycle rule is present.

## 3. Rego v1 Code Gen Guardrails

To prevent rule compilation failures, you must adhere strictly to OPA Rego v1 syntax specifications:
* **Import Declaration:** Every generated Rego rule file must explicitly declare `import rego.v1` at the top of the file.
* **Explicit 'if' Keyword:** Use the explicit `if` keyword for rule definitions. Avoid the deprecated implicit style.
* **Safe Object Lookup:** Never access deep fields directly (e.g. `bucket.additionalAttributes.lifecycle.rule[_]`). You must use nested `object.get` lookups to prevent undefined evaluations when properties are missing in raw payloads:
  ```rego
  additionalAttributes := object.get(bucket, "additionalAttributes", {})
  lifecycle := object.get(additionalAttributes, "lifecycle", {})
  rules := object.get(lifecycle, "rule", [])
  ```
