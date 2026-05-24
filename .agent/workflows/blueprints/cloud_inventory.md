# Cloud Inventory Blueprint Agent

This playbook defines the instructions, guardrails, and reference patterns for AI agents scaffolding or maintaining native cloud resource inventory integrations in the Jula Evidence Collector.

## When to Use This Agent

Use this agent when the integration target is a cloud provider's resource inventory API that requires a vendor-specific SDK. The defining characteristic is that these APIs use structured query languages and return protobuf or typed JSON responses through SDK-managed pagination, rather than generic REST/HTTP calls.

Current and planned targets:

| Cloud | Service | SDK | Query Mechanism | Pagination |
|---|---|---|---|---|
| GCP | Cloud Asset Inventory | `cloud.google.com/go/asset` | gRPC SearchAllResources | Iterator (protobuf) |
| AWS | Config | `aws-sdk-go-v2/service/configservice` | SelectResourceConfig SQL | SDK Paginator |
| Azure | Resource Graph | `azure-sdk-for-go` (planned) | Kusto Query Language (KQL) | NextLink token |

If the integration target is a SaaS vendor with a REST API and an OpenAPI/Swagger spec, use the **OpenAPI Blueprint Agent** instead.

---

## Workspace Root Convention

Both `jula-evidence-collector` and `jula-compliance-policies` repositories must be checked out as sibling directories under a single workspace root folder:

```
workspace/
  jula-evidence-collector/    # Go provider code, YAML configs, automation
  jula-compliance-policies/   # Rego normalizers, compliance policies, fixtures
```

When generating cross-repo stubs (e.g., Rego normalizers), use relative paths from the collector root: `../jula-compliance-policies/policies/normalization/<cloud>/`.

---

## Scaffold Mode: Building a New Cloud Integration

When scaffolding a new cloud provider integration, generate the following artifacts in order.

### 1. Go Provider Package

Create a new package at `internal/providers/<cloud>/` containing:

**Provider struct and constructor:**

- Follow the interface-driven design established in `internal/providers/gcp/cai.go`. Define an abstraction interface for the cloud client (e.g., `AssetClient` for GCP, `SelectResourceConfigAPIClient` for AWS) to enable dependency injection during testing.
- The constructor must authenticate using the cloud vendor's standard credential chain (e.g., Application Default Credentials for GCP, environment/IMDS chain for AWS). Never accept raw credentials as constructor parameters.
- Include a `Close()` method for interface symmetry, even if the underlying client uses HTTP and has no persistent connection to tear down.

**Extract method:**

- Accept `(ctx context.Context, evidenceID string, cfg <ExtractionConfig>, runID string)` matching the signature pattern in both existing providers.
- Use the SDK's native paginator or iterator to traverse all result pages. Aggregate results into a `[]json.RawMessage` or `[]map[string]interface{}` slice.
- Marshal the aggregated results into `types.Finding.RawData` as opaque JSON bytes. The provider must never interpret, transform, or restructure the cloud API response.
- Set `Finding.Provider` to a descriptive lowercase identifier (e.g., `gcp_cai`, `aws_config`, `azure_resource_graph`).

**Config loader:**

- Follow the `LoadCAIConfigs` / `LoadAWSConfigExtractions` pattern: read a YAML file, unmarshal into a typed map keyed by Evidence ID, validate that the file is non-empty, and enforce path traversal prevention using `filepath.Clean` with `..` rejection.

**Reference implementations:**

- GCP pattern (gRPC iterator): `internal/providers/gcp/cai.go`
- AWS pattern (SDK paginator): `internal/providers/aws/config.go`

### 2. YAML Extraction Config

Create the extraction config at `configs/blueprints/native/<cloud>_<service>.yaml`.

Each entry in the YAML file maps an Evidence ID to a specific query against the cloud inventory API:

```yaml
DCH-10:
  evidence_id: "EVID-DCH-10"
  description: "Human-readable description of what this extraction collects"
  provider: "<cloud>_<service>"
  query: "The vendor-specific query string"
```

Follow the established format in `configs/blueprints/native/gcp_cai.yaml` and `configs/blueprints/native/aws_config.yaml`. Include any vendor-specific fields (e.g., `scope`, `asset_types`, `search_type` for GCP).

### 3. Rego Normalizer Stubs

Create stub normalizers in the compliance policies repository at `../jula-compliance-policies/policies/normalization/<cloud>/`.

For each resource type that requires compliance evaluation, create a `.rego` file following the established pattern:

```rego
package normalization.<cloud>.<resource_type>
import rego.v1

normalize(resource) = normalized if {
    # Extract nested properties using object.get for nil-safety
    settings := object.get(resource, "settings", {})

    normalized := {
        "schema_field": object.get(settings, "vendor_field", <default_value>)
    }
}
```

Reference implementations:

- `policies/normalization/gcp/database.rego`
- `policies/normalization/gcp/storage.rego`

### 4. Unit Tests

Create `_test.go` files alongside the provider code:

- Test the constructor with mock credentials (including structurally valid RSA private keys for GCP, per the learning documented in `.jules/wrench_tests.md`).
- Test the `Extract` method by injecting a mock client that implements the abstraction interface, returning canned responses.
- Test the config loader with valid YAML, empty YAML, and path traversal attempts.
- Test negative cases: network timeouts, malformed JSON responses, empty result sets.

Reference implementations:

- `internal/providers/gcp/cai_test.go`
- `internal/providers/aws/config_test.go`

---

## Maintenance Mode: Updating an Existing Integration

When a cloud API introduces new resource types, deprecates fields, or changes pagination behavior:

1. **Update the YAML extraction config** by adding new Evidence entries or modifying existing queries.
2. **Update or add Rego normalizers** in `jula-compliance-policies` to handle the new resource structure. Always use `object.get` with fallback defaults to handle both old and new field names gracefully.
3. **Update unit tests** to cover the new resource types or field changes with fresh mock responses.
4. **Do not modify the Go provider code** unless the cloud SDK itself introduces breaking changes to its pagination or query interface.

---

## Architectural Guardrails

### Strict Agnosticism Rule

Normalized schema outputs in Rego must remain completely cloud-agnostic. Map provider-specific terms (e.g., AWS `StorageEncrypted`, GCP `diskEncryptionKey`) directly to standard schema fields (e.g., `encrypted_at_rest`). Never leak AWS, GCP, Azure, or any vendor terminology into normalized schemas.

### Finding.RawData Immutability Rule

> [!CAUTION]
> NEVER modify the `Finding.RawData` byte slice after it is assigned.

Treat `RawData` as a read-only payload. The orchestrator will cryptographically hash this field for provenance verification. Any mutation after assignment will break the hash chain.

### Nil-Pointer Safety Rule

Cloud APIs drift frequently. Provider code must handle missing or null keys gracefully:

- Never assume a JSON key path exists in unmarshalled responses.
- Use defensive programming when traversing `map[string]any` structures.
- Check for `nil` values before dereferencing any nested properties.
- Providers must never panic under any input condition.

### Rego v1 Standards

All generated Rego files must strictly adhere to OPA Rego v1 syntax:

- Declare `import rego.v1` at the top of every file.
- Use the explicit `if` keyword for rule definitions (no deprecated implicit style).
- Use `object.get` for all nested field access to prevent undefined evaluations.

### File Permission Standards

- Directories containing extracted fixtures or test payloads must use `0700` permissions.
- Individual payload files must use `0600` permissions.

### Air-Gapped Testing Rule

Provider unit tests must never depend on real cloud networks or actual API endpoints. All cloud SDK calls must be mocked using interface-driven dependency injection with canned responses.
