# Jula: Feature Inventory

Jula is a compliance-as-code automation platform built in Go. It collects evidence from cloud and SaaS providers, evaluates it against machine-readable policy, and produces cryptographically signed audit artifacts. The system is designed around zero-trust principles: every evidence payload is hashed, every verdict is signed, and every pipeline step is attested.

## Architecture

Jula is structured as a Go monorepo with four independent modules connected through a shared core library.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Governor    │     │  Collector   │     │  Assessor   │
│  (Policy     │     │  (Evidence   │     │  (Policy     │
│   Authoring) │     │   Gathering) │     │   Engine)    │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       └────────────┬───────┘────────────────────┘
                    │
              ┌─────┴─────┐
              │   Core     │
              │  (Shared   │
              │   Library) │
              └────────────┘
```

---

## Collector

The collector is a headless evidence-gathering engine. It reads declarative YAML integration files, authenticates against each provider's API, extracts compliance-relevant data, and writes cryptographically signed evidence bundles to cloud object storage.

### Universal REST Engine

A provider-agnostic HTTP execution engine that drives all evidence collection through declarative YAML configurations. No provider-specific code is required to add a new integration.

- **Declarative integration YAML** defines vendor identity, auth flow, endpoints, headers, query parameters, and pagination strategy
- **Environment variable interpolation** with path-escape safety to prevent SSRF and path traversal (`${VAR_NAME}` syntax)
- **Rate limit handling** with exponential backoff, automatic retry on HTTP 429/5xx, and `Retry-After` header support
- **Strict pagination enforcement** prevents data loss by rejecting responses that contain `rel=next` Link headers when the integration config lacks pagination instructions
- **RFC 5988 Link header pagination** and JSON path-based cursor pagination for APIs that use response body fields
- **HTTP 404 tolerance** via `allow_404` flag for optional endpoints that may not exist in every organization
- **Credential sensitivity** with automatic redaction of auth fields in logs and JSON serialization

### Multi-Cloud Authentication

Seven authentication strategies are implemented, each as a standalone signer module. All signers produce `ErrMissingCredentials` when credentials are absent, enabling graceful skip behavior at the orchestrator level.

- **Bearer Token** (`bearer`) for GitHub, generic REST APIs
- **OAuth2 Client Credentials** (`oauth2`) for OAuth2-based SaaS platforms, with full token exchange flow
- **GCP Application Default Credentials** (`gcp_adc`) using `google.FindDefaultCredentials` with cloud-platform scope
- **AWS Signature V4** (`aws_sigv4`) with manual canonical request construction, no AWS SDK dependency
- **Azure Managed Identity** (`azure_identity`) with IMDS metadata service token acquisition and in-memory token caching
- **OCI HTTP Signature** (`oci_cavage`) implementing RFC 7616 Cavage HTTP signatures with RSA-SHA256
- **Alibaba Cloud / Tencent Cloud HMAC** (`ali_tencent_hmac`) with TC3-HMAC-SHA256 canonical signing

### Concurrent Extraction Pipeline

- **Bounded concurrency** with configurable goroutine pool (semaphore pattern) for parallel evidence extraction
- **Per-evidence timeout** with independent `context.WithTimeout` for each extraction job
- **Three-category error classification**: missing credentials (skip), real extraction failures (error), and successful extractions
- **Partial failure tolerance** with the pipeline succeeding if any evidence is collected, even when some extractions fail
- **Graceful credential skipping** where integrations without configured credentials are logged as warnings and excluded from failure counts

### Evidence Delivery

- **Multi-cloud object storage** via a unified `objstore` interface supporting GCS, S3, and local filesystem
- **AWS S3 with SigV4 signing** implemented from scratch without the AWS SDK
- **ECDSA-P256 evidence signing** where every evidence payload is SHA-256 hashed and signed with a per-environment private key
- **Signed manifest generation** containing evidence file paths, hashes, and a top-level signature for tamper detection
- **Platform auto-detection** identifying GCP, AWS, or local environments from standard environment variables

### Pre-Built Integrations

Seven cloud and SaaS integrations ship out of the box, each defined as a standalone YAML file:

- **GitHub** (Pull requests, branches, organization members)
- **GCP** (Cloud Asset Inventory via REST)
- **AWS** (Placeholder via SigV4)
- **Azure** (Placeholder via Managed Identity)
- **OCI** (Placeholder via Cavage HTTP Signatures)
- **Alibaba Cloud** (Placeholder via HMAC)
- **Tencent Cloud** (Placeholder via HMAC)

---

## Assessor

The assessor is a policy execution engine that reads collected evidence, runs it through OPA Rego policies, and produces cryptographically signed compliance verdicts.

### Policy Evaluation

- **OPA Rego policy engine** for declarative compliance rule evaluation
- **Evidence ingestion** from cloud object storage (GCS, S3) or local filesystem via signed manifests
- **Manifest integrity verification** validating SHA-256 hashes and ECDSA signatures before processing
- **Per-evidence policy matching** routing evidence to the correct Rego rules based on evidence ID
- **Active rules configuration** via `active_rules.json` for selective policy enablement

### Signed Verdicts

- **ECDSA-P256 verdict signing** where every compliance verdict is cryptographically signed
- **Verdict structure** containing evidence ID, pass/fail status, rule violations, timestamp, and signature
- **Tamper-evident audit trail** enabling downstream systems to verify verdict authenticity

---

## Governor

The governor is the policy authoring and compliance catalog management layer. It uses AI-assisted workflows to transform human-readable compliance frameworks into machine-executable policy.

### AI-Powered Policy Pipeline

A multi-stage prompt pipeline that converts compliance catalog prose into executable OPA Rego rules:

- **`setup_01_build_integration.md`** generates declarative REST integration YAML from API documentation
- **`setup_02_build_translator.md`** creates data transformation mappings from raw API responses to normalized schemas
- **`setup_03_extract_requirements.md`** extracts machine-readable requirements (parameter, operator, expected value) from compliance control prose
- **`setup_04_generate_policy.md`** generates OPA Rego rules from extracted requirements
- **`remediate_01_heal_translator.md`** auto-repairs broken translator mappings when API schemas drift

### Import Tool

- **CSV catalog ingestion** parsing compliance frameworks (CIS benchmarks, SOC2, etc.) from CSV format
- **Cascading provider resolution** determining the target cloud provider via three strategies: CSV column, control ID parsing (e.g., `CIS-GCP-EASY-1` → `gcp`), or CLI `--provider` flag
- **Workspace-aware filtering** skipping controls for providers not enabled in `workspace.yaml`
- **Idempotent processing** with stateful resume that skips already-triaged controls
- **Dual-tier AI failover** with primary and fallback LLM endpoints, per-tier retry logic, and automatic failover
- **Proactive rate limit telemetry** reading `X-RateLimit-Remaining` headers and backing off before hitting limits
- **LLM hallucination guard** overriding AI-generated provider fields to match workspace-resolved values

### Workspace Configuration

- **`workspace.yaml`** as the central configuration for organization identity and active cloud providers
- **Per-provider `doc_root`** injected into AI prompts for grounded documentation references

### Policy Bundle Signing

- **Tarball bundling** of policies and engine configuration into a distributable `governor-policy-bundle.tar.gz`
- **SHA-256 bundle hashing** with ECDSA signing via `core/cmd/sign-bundle`
- **Signed manifest** (`bundle-manifest.json`) for downstream verification of policy integrity

---

## Core Library

Shared infrastructure used by all modules.

### Cryptography (`core/pkg/crypto`)

- **Evidence signing** with ECDSA-P256 key pairs (PEM-encoded)
- **Bundle signing** for policy distribution verification
- **Verdict signing** for tamper-evident compliance results

### Object Store (`core/pkg/objstore`)

- **Unified interface** abstracting GCS, S3, and local filesystem behind a common `Store` interface
- **URL-based factory** (`gs://`, `s3://`, or local path) for zero-config store initialization
- **GCS integration** using Google Cloud Storage JSON API with OAuth2
- **S3 integration** with manual AWS Signature V4 signing (no SDK dependency)
- **Local filesystem** adapter for development and testing

### Safe HTTP (`core/pkg/safehttp`)

- **SSRF-hardened HTTP client** for outbound requests with timeout enforcement

---

## CI/CD & Supply Chain Security

Eight GitHub Actions workflows automate the full build, test, deploy, and assurance lifecycle.

### Build & Deploy Pipelines

- **Per-module CI** (`ci-collector.yml`, `ci-assessor.yml`, `ci-governor.yml`, `ci-core.yml`) with independent test, lint, build, and deploy stages
- **Dual-cloud container deployment** pushing Docker images to both GCP Artifact Registry and AWS ECR
- **Cloud Run deployment** for serverless execution on GCP
- **Path-filtered triggers** ensuring only affected modules rebuild on push

### Supply Chain Attestation

- **SLSA Provenance v1** attestation on every container image via `actions/attest-build-provenance`
- **SHA-pinned GitHub Actions** across all 11 action dependencies with version comments for auditability
- **Policy bundle signing** workflow for distributing verified governance policy

### Release Management

- **Automated releases** via `release-please` with conventional commit parsing and changelog generation
- **Multi-artifact release pipeline** building collector, assessor, and signing artifacts for Linux and Darwin (amd64/arm64)
- **Build provenance attestation** on every release binary

### Canary Pipeline

- **Scheduled daily canary** (`pipeline-canary.yml`) running at 2:00 AM UTC via cron
- **Ephemeral signing key generation** per canary run (no persistent secrets required for basic validation)
- **Graceful no-evidence handling** where the assessor is skipped when no integrations have credentials configured
- **Build and boot validation** confirming both binaries compile and execute without crashes

### Self-Healing Pipeline

- **Schema drift remediation** (`pipeline-self-heal.yml`) triggered via `repository_dispatch` when cloud API schemas change
- **AI-driven patch generation** using the governor's heal prompt to auto-repair broken translator mappings
- **Automated pull request creation** with descriptive remediation reports and `autopilot` labeling

---

## Infrastructure

### Terraform

- **GCP infrastructure** provisioned via Terraform
- **AWS infrastructure** provisioned via Terraform
- **Dual-cloud deployment** architecture supporting simultaneous GCP Cloud Run and AWS ECS/Lambda targets

---

## Testing

- **Comprehensive unit test coverage** across all modules with `_test.go` files alongside production code
- **Table-driven tests** following Go testing conventions
- **Containerized test execution** via `docker run golang:1.25` for reproducible CI environments
- **Test isolation** with environment variable sandboxing and mock HTTP servers
