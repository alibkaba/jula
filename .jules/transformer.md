# AI Developer Guardrails: Transformer Mappings

This document serves as the system instruction for AI agents and developer tools when creating or modifying compliance transformer mappings in this repository.

## Mappings Mandate

The compliance pipeline transforms raw, opaque provider-specific findings (`RawData`) into cloud-agnostic, schema-validated JSON structures (`NormalizedData`) before packaging them as Evidence. This separation decouples downstream OPA policies from cloud-provider API drift and custom schema versions.

---

## Strict Guardrails

### 1. Strict Immutability Rule

> [!CAUTION]
> NEVER modify the original `finding.RawData` byte slice.
- Treat `finding.RawData` as a read-only stream.
- When unmarshalling, parse into a new, independent variable.
- Any attempt to write to or slice-reassign `RawData` directly is a critical security violation.

### 2. Agnostic-Only Rule

> [!IMPORTANT]
> Normalized schema outputs MUST remain completely cloud-agnostic.
- Mappings must map provider-specific terms (e.g. AWS `StorageEncrypted`, GCP `diskEncryptionKey`) directly to standard schema fields (e.g. `encrypted_at_rest`).
- Never leak AWS, GCP, Azure, GitHub, or Aikido terminology into standard schemas.
- All schema structures must use lowercase snake_case JSON field tags and be defined in the `internal/transformer/schemas` package.

### 3. Nil-Pointer Safety Rule

> [!WARNING]
> APIs drift frequently; mappings must handle missing or null keys gracefully.
- Never assume a JSON key path exists in `RawData`.
- Use defensive programming when traversing unmarshalled `map[string]any` structures or structures containing pointers.
- Check for `nil` values before dereferencing any nested properties. Mappers must never panic under any input condition.

---

## Target Schemas

### StorageSchema
Maps block or object storage entities (e.g. S3 buckets, GCS buckets) to a standard schema.
- `public_access_disabled` (bool)
- `encrypted_at_rest` (bool)
- `versioning_enabled` (bool)

### DatabaseSchema
Maps database configurations (e.g. AWS RDS, GCP Cloud SQL) to a standard schema.
- `encrypted_at_rest` (bool)
- `require_tls` (bool)
- `publicly_accessible` (bool)

---

## Code Generation Pattern

When generating new mapping code, follow this pattern:

```go
func transformExample(finding types.Finding) (json.RawMessage, error) {
	// 1. Unmarshal into a local, temporary representation
	var raw map[string]any
	if err := json.Unmarshal(finding.RawData, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal finding: %w", err)
	}

	// 2. Safely extract values using helper functions or nil checks
	// ...

	// 3. Populate and return the target agnostic schema
	// ...
}
```
