# Internal: Core Domain Logic

This directory contains the private domain logic of the Jula Evidence Collector. Everything under `internal/` is inaccessible to external Go modules by design, enforced by the Go compiler itself.

## Package Map

```
internal/
├── engine/       Orchestrator and concurrent extraction pipeline.
├── providers/    Cloud API extractors and evidence ingestion modules.
├── mappers/      SOC 2 policy evaluation and criteria mapping logic.
└── reporter/     Output formatting for stdout and cloud storage (GCS).
```

### engine/

The `Orchestrator` is the central coordinator. It accepts a set of registered `Provider` implementations, executes them concurrently within a configurable worker pool, and aggregates the resulting `Finding` objects into a unified report. All error handling is resilient: a single provider failure does not halt the pipeline.

### providers/

Each provider is an isolated module that implements the `providers.Provider` interface (`Name`, `Validate`, `Extract`). The registry pattern allows providers to self-register at init time or be instantiated dynamically.

| Provider | Package | Extraction Method |
| :--- | :--- | :--- |
| Google Cloud Platform | `providers/gcp/` | Native API queries (IAM, KMS, SQL, Compute, Storage, Audit Logging) |
| BYOE FileDrop | `providers/filedrop/` | Cloud bucket watcher with dual-track processing (JSON parsing or SHA-256 hashing) |

The `filedrop` provider is not registered via `init()` because it requires runtime configuration (bucket name, storage client). It is instantiated via the `New()` constructor.

### mappers/

The mapping engine evaluates raw `Finding` objects against declarative rules defined in `configs/soc2_mapping.json`. It resolves each finding to specific AICPA Trust Services Criteria (e.g., CC6.1, CC7.1) and applies policy thresholds from `configs/gcp_policy.json`.

### reporter/

Handles final output serialization. The standard reporter writes structured JSON to stdout. The GCS reporter uploads cryptographically signed evidence bundles directly to the client's own cloud storage vault.

## Contributing

When adding a new provider, follow this pattern:

1. Create a new package under `providers/` (e.g., `providers/aws/`).
2. Implement the `providers.Provider` interface.
3. Register the provider in `providers/registry.go` (for static providers) or instantiate it dynamically in the CLI layer.
4. Add the provider name to the validation list in `cmd/jula/extract.go`.
5. Write tests with a mock client that satisfies the relevant cloud SDK interface.
