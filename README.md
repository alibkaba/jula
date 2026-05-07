# Jula Evidence Collector

**Primary Language:** Go (Golang)

A high-performance, open-source CLI tool that programmatically extracts infrastructure state to generate continuous compliance telemetry. 

## Zero-Friction Compliance

Modern compliance platforms charge massive premiums for onboarding, API mapping, and implementation. The **Jula Evidence Collector** is designed to disrupt that model by commoditizing the most complex part of compliance: automated, cryptographically signed evidence gathering.

By pairing this containerized evidence collector with standard document management and ticketing tools, engineering teams can achieve continuous compliance without paying a SaaS middleman, enduring lengthy implementations, or accepting vendor lock-in.

### Supported Frameworks

*   **MVP Focus:** SOC 2 (Type II)
*   **Roadmap (Later Date):**
    *   CIS GCP Foundations Benchmark
    *   NIST (800-53 / CSF)
    *   HIPAA Security Rule
    *   PCI-DSS
    *   ISO 27001

## Quick Start
```bash
go run cmd/jula/main.go
```

## Architecture

1. **The Core Engine:** Handles CLI execution, concurrent Go routines, logging, and JSON report generation.
2. **The Providers:** Isolated modules that handle API authentication and state extraction.
3. **The Mappers:** Configuration files that map the raw telemetry from Providers to specific compliance frameworks.
4. **The Reporters:** Deliver signed, cryptographically verifiable evidence directly to the client's own cloud storage vault (S3, GCS, Azure Blob), giving auditors direct access without a SaaS middleman.
5. **Deployment & Compatibility:** The architecture is fundamentally cloud-agnostic and compiles to a standard Docker container.
    * **Google Cloud (GCP):** Fully configured, rigorously tested, and actively deployed in production.
    * **AWS & Azure:** The core extraction engine supports these environments, but native API providers are currently in development. We welcome community collaboration from teams looking to implement and validate the AWS or Azure pathways.

## Directory Structure

```
jula-evidence-collector/
├── cmd/jula/                  # CLI entrypoint, command parsing, and flag validation.
├── internal/                  # Core domain logic (engine, providers, mappers, reporter).
│   ├── engine/                #   Orchestrator: concurrent extraction pipeline.
│   ├── providers/             #   Cloud API extractors (GCP) and BYOE FileDrop.
│   ├── mappers/               #   SOC 2 policy evaluation and criteria mapping.
│   └── reporter/              #   Output formatting (stdout, GCS upload).
├── pkg/                       # Shared libraries (crypto, types) importable by external tools.
├── configs/                   # Declarative rules: mapping configs, policies, and JSON schemas.
│   └── schemas/               #   BYOE validation schemas (e.g., vulnerability scans).
├── frameworks/                # Public compliance framework documentation and control status.
│   └── soc2/                  #   SOC 2 TSC control-by-control coverage tracking.
├── blueprints/remediation/    # Parameterized Terraform blueprints for fixing violations.
├── deploy/terraform/          # Internal IaC for deploying Jula itself (Cloud Run, Scheduler).
├── Dockerfile                 # Multi-stage build: golang:alpine → scratch (zero attack surface).
└── LICENSE                    # Business Source License (BSL 1.1).
```

Each major directory contains its own `README.md` with localized context for contributors and evaluators. Start with [`internal/README.md`](internal/README.md) for the Go engine, [`configs/README.md`](configs/README.md) for the declarative rule system, or [`deploy/terraform/README.md`](deploy/terraform/README.md) for infrastructure operations.

## Supported SOC 2 Trust Services Criteria (TSC)

Jula Evidence Collector is designed to programmatically fulfill the evidentiary requirements for specific SOC 2 Trust Services Criteria.

### Scope

Our current implementation strictly targets the following criteria categories:

* **Security (Common Criteria)**
* **Confidentiality**
* **Availability**

> **Note:** Privacy and Processing Integrity are currently **out of scope** for automated collection and are not supported.

### How We Map Controls

We utilize two distinct architectural patterns to gather evidence across diverse environments without relying on brittle third-party APIs:

1. **Native Infrastructure Extraction (Specific Values):** For cloud-native controls (e.g., IAM, Encryption at Rest, Firewalls), Jula directly queries AWS, GCP, and Azure APIs. We parse the telemetry to generate deterministic, pass/fail state evaluations.
2. **Bring Your Own Evidence (BYOE) / FileDrop:** For tools lacking native APIs, procedural controls, or HR policies, Jula watches a designated cloud storage bucket (S3/GCS) and processes files in two ways:
    * **Data Parsing:** Ingests standardized JSON (like vulnerability scans), validates the schema, and evaluates the specific values.
    * **Cryptographic Hashing:** Treats PDFs, CSVs, and Text files (like HR Handbooks, NDAs, or Access Matrices) as opaque artifacts. Jula generates a SHA-256 hash and timestamp to cryptographically prove the document's existence and maintenance cadence without ever reading sensitive internal text.

### Detailed Control Mappings

For a granular, control-by-control breakdown of our coverage, please refer to our dedicated framework documentation:

* [SOC 2 TSC Control Status](frameworks/soc2/README.md)

## Licensing

This project is licensed under the Business Source License (BSL 1.1). See the [LICENSE](LICENSE) file for details.
