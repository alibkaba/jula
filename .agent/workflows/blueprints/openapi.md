# OpenAPI Blueprint Agent

This playbook defines the instructions, guardrails, and reference patterns for AI agents scaffolding or maintaining SaaS REST API integrations in the Jula Evidence Collector using the blueprint-driven universal REST engine.

## When to Use This Agent

Use this agent when the integration target is a SaaS vendor with a REST API, especially one that publishes an OpenAPI or Swagger specification. The defining characteristic of this integration path is that it requires **zero Go code changes**. The universal REST engine handles all HTTP execution, authentication, pagination, and environment variable interpolation based entirely on a YAML blueprint file.

Current production integrations using this path:

- **Aikido** (OAuth2, multi-endpoint): `configs/blueprints/openapi/aikido.yaml`
- **GitHub** (Bearer token, Link header pagination): `configs/blueprints/openapi/github.yaml`

If the integration target is a cloud provider's resource inventory API that requires a vendor-specific SDK (GCP CAI, AWS Config, Azure Resource Graph), use the **Cloud Inventory Blueprint Agent** instead.

---

## Workspace Root Convention

Both `jula-evidence-collector` and `jula-compliance-policies` repositories must be checked out as sibling directories under a single workspace root folder:

```
workspace/
  jula-evidence-collector/    # Blueprint YAML configs, universal REST engine
  jula-compliance-policies/   # Rego normalizers, compliance policies, fixtures
```

When generating Rego normalizer stubs, use relative paths from the collector root: `../jula-compliance-policies/policies/normalization/<vendor>/`.

---

## Scaffold Mode: Building a New SaaS Integration

When scaffolding a new SaaS vendor integration, you need to generate only a YAML blueprint file and optionally a Rego normalizer stub. No Go code is required.

### 1. YAML Blueprint File

Create the blueprint at `configs/blueprints/openapi/<vendor>.yaml` conforming to the JSON Schema defined at `configs/schemas/openapi-blueprint.schema.json`.

**Structure:**

```yaml
vendor_name: "<vendor_lowercase>"
base_url: "https://api.vendor.com/v1"
auth_flow:
  type: "oauth2"           # or "bearer"
  token_url: "https://api.vendor.com/oauth/token"    # required for oauth2
  client_id_env: "VENDOR_CLIENT_ID"                  # required for oauth2
  client_secret_env: "VENDOR_CLIENT_SECRET"          # required for oauth2
  token_env: "VENDOR_API_TOKEN"                      # required for bearer
endpoints:
  "/resources":
    erl_id: "E-XXX-NN"
    description: "Human-readable description of what this endpoint provides"
  "/resources/{id}/details":
    erl_id: "E-XXX-MM"
    description: "Detailed resource configuration"
    headers:
      Accept: "application/json"
    pagination:
      next_url_field: "header.Link"    # or a JSON body field path like "next"
      max_pages: 10
    allow_404: true
```

**Reference implementations:**

- OAuth2 with multi-endpoint collision handling: `configs/blueprints/openapi/aikido.yaml`
- Bearer token with Link header pagination: `configs/blueprints/openapi/github.yaml`

### 2. Authentication Configuration

The `auth_flow` block supports two strategies:

**OAuth2 Client Credentials:**

- Set `type: "oauth2"`.
- Provide `token_url`, `client_id_env`, and `client_secret_env`.
- The engine exchanges credentials via a POST to the token URL using HTTP Basic authentication (base64-encoded `client_id:client_secret`) and extracts the `access_token` from the JSON response.

**Bearer Token:**

- Set `type: "bearer"`.
- Provide `token_env` with the environment variable name containing the static API token.

> [!CAUTION]
> **Log Leak Prevention:** The `OpenAPIBlueprint` and `AuthFlowConfig` structs implement custom `MarshalJSON()` and `Redacted()` methods that replace `client_secret_env` and `token_env` values with `*REDACTED*` whenever the struct is serialized or logged. You must write only the **literal uppercase name of the environment variable** (e.g., `AIK_SECRET_KEY`, `GITHUB_TOKEN`) into the `_env` fields. Never inject a raw cleartext token string. This ensures that if the blueprint is ever printed, logged, or serialized to disk, no actual secrets are exposed.

### 3. Endpoint Mapping

Map each compliance-relevant API endpoint to an ERL ID. When reading an OpenAPI/Swagger specification:

- Identify GET endpoints that return resource configurations, inventories, scan results, or audit data.
- Determine if the endpoint supports pagination (check for Link headers in the spec or `next` fields in response schemas).
- Set `allow_404: true` for endpoints that return optional resources (e.g., a CODEOWNERS file that may not exist).

### 4. The `jula_erl=` Collision Pattern

In the blueprint YAML, the `endpoints` block is a map where the key is the URI path. When a single SaaS API endpoint returns a heavy dataset that fulfills multiple distinct ERL requirements, you cannot reuse the same URI key twice in a YAML map.

**The solution:** Append a virtual query parameter `jula_erl=E-XXX-NN` to create unique map keys:

```yaml
endpoints:
  "/issues/export?format=json&filter_status=open&jula_erl=E-MNT-03":
    erl_id: "E-MNT-03"
    description: "Patch Management Audits (Open Vulnerabilities)"
  "/issues/export?format=json&filter_status=open&jula_erl=E-VPM-11":
    erl_id: "E-VPM-11"
    description: "Open Vulnerability Scan"
```

The `CleanPath` function in the universal REST engine automatically strips `jula_erl=` parameters before firing the HTTP request, guaranteeing clean upstream API calls. The vendor's API never sees this parameter.

Production examples of this pattern are visible in `configs/blueprints/openapi/aikido.yaml` where `/issues/export` and `/report/ciScans` each appear multiple times with different `jula_erl=` suffixes.

### 5. Pagination Configuration

Two pagination strategies are supported:

**RFC 5988 Link Header (common in GitHub-style APIs):**

```yaml
pagination:
  next_url_field: "header.Link"
  max_pages: 5
```

**JSON Body Field (cursor-based APIs):**

```yaml
pagination:
  next_url_field: "pagination.next_url"
  max_pages: 10
```

Always set a bounded `max_pages` value. The engine defaults to 100 as a safety threshold if none is specified.

> [!WARNING]
> **Strict Pagination Enforcement:** The engine will reject responses that contain a `rel="next"` Link header if the endpoint configuration does not include pagination instructions. This prevents silent data truncation. If the vendor API paginates, you must configure it.

### 6. Environment Variable Interpolation

Endpoint paths support `${VAR_NAME}` interpolation for dynamic values:

```yaml
"/repos/${GITHUB_ORG}/${GITHUB_REPO}/commits":
  erl_id: "E-AST-22"
  description: "Repository Commit Provenance"
```

The engine resolves these at runtime from environment variables. Path variables are URL-escaped to prevent SSRF and path traversal. Header values are interpolated without escaping. Unresolved variables (where the env var is not set) will cause the engine to reject the request with a clear error.

### 7. Rego Normalizer Stubs (Optional)

If the vendor's data feeds compliance evaluation rules, create stub normalizers in `../jula-compliance-policies/policies/normalization/<vendor>/`:

```rego
package normalization.<vendor>.<resource_type>
import rego.v1

normalize(resource) = normalized if {
    data := object.get(resource, "data", {})

    normalized := {
        "schema_field": object.get(data, "vendor_field", <default_value>)
    }
}
```

Follow the Rego v1 standards defined in the Architectural Guardrails section below.

---

## Maintenance Mode: Updating an Existing Integration

When a SaaS vendor changes its API:

1. **Endpoint changes:** Update or add endpoint entries in the existing blueprint YAML. If an endpoint is removed, delete its entry. If a new endpoint is added, map it to the appropriate ERL ID.
2. **Auth flow rotation:** Update the `auth_flow` block if the vendor migrates from Bearer to OAuth2 or changes their token URL.
3. **Pagination changes:** Add, modify, or remove `pagination` blocks as the vendor updates its pagination strategy.
4. **Field deprecations:** Update corresponding Rego normalizers to handle both old and new field names using `object.get` with fallback defaults.
5. **No Go code changes required.** The universal REST engine is fully data-driven. All maintenance is YAML-only unless the vendor introduces a fundamentally new auth strategy not supported by the engine (in which case the engine itself would need extension).

---

## Architectural Guardrails

### Zero-Code Guarantee

OpenAPI integrations must never require modifications to Go source code. If a vendor's API cannot be fully described by the blueprint YAML schema, evaluate whether the vendor belongs in the native Cloud Inventory path instead.

### Credential Isolation Rule

> [!CAUTION]
> Never hardcode credentials, tokens, or secrets in blueprint YAML files.

All sensitive values must be referenced by environment variable name using the `_env` suffix convention:

- `client_id_env: "VENDOR_CLIENT_ID"` (not the actual client ID)
- `client_secret_env: "VENDOR_SECRET"` (not the actual secret)
- `token_env: "VENDOR_TOKEN"` (not the actual token)

### Strict Agnosticism Rule

If Rego normalizers are generated, their output schemas must remain completely cloud-agnostic. Map vendor-specific terms to standard schema fields. Never leak vendor terminology into normalized schemas.

### Rego v1 Standards

All generated Rego files must strictly adhere to OPA Rego v1 syntax:

- Declare `import rego.v1` at the top of every file.
- Use the explicit `if` keyword for rule definitions.
- Use `object.get` for all nested field access to prevent undefined evaluations.

### File Permission Standards

- Directories containing extracted fixtures or test payloads must use `0700` permissions.
- Individual payload files must use `0600` permissions.

### Schema Validation

Validate all generated blueprint YAML files against the JSON Schema at `configs/schemas/openapi-blueprint.schema.json` before committing. The schema enforces required fields (`vendor_name`, `base_url`, `auth_flow`, `endpoints`) and validates auth flow type enumerations.

### Air-Gapped Testing Rule

Integration testing must use the local HTTP mock server pattern established in `tests/e2e/mocks/server.go`. Never make real HTTP calls to vendor APIs during testing. Rego normalizer tests must run containerized using the `openpolicyagent/opa` Docker image.
