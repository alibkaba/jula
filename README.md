# Jula Evidence Collector

[![CI/CD Pipeline](https://github.com/alibkaba/jula-evidence-collector/actions/workflows/main.yml/badge.svg)](https://github.com/alibkaba/jula-evidence-collector/actions/workflows/main.yml)
[![GitHub Release](https://img.shields.io/github/v/release/alibkaba/jula-evidence-collector?color=blue&logo=github)](https://github.com/alibkaba/jula-evidence-collector/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/alibkaba/jula-evidence-collector?logo=go)](https://go.dev/)
[![Go Report Card](https://goreportcard.com/badge/github.com/alibkaba/jula-evidence-collector)](https://goreportcard.com/report/github.com/alibkaba/jula-evidence-collector)
[![License](https://img.shields.io/badge/License-BSL_1.1-orange.svg)](LICENSE)

**Primary Language:** Go (Golang)

A high-performance, open-source CLI tool that programmatically extracts infrastructure state from multiple cloud providers to generate continuous compliance telemetry. Jula operates as a "Collector-Only" engine: it extracts raw infrastructure configuration, cryptographically signs it, and stores immutable evidence artifacts. No evaluation, no dashboards, no opinions.

## The Philosophy: Attestation Engineering vs. Traditional GRC

Modern compliance platforms charge massive premiums for monolithic dashboards, forcing you to adopt heavy, misaligned workflows and endpoint agents. The **Jula Evidence Collector** is designed to disrupt that model by treating compliance as an engineering problem rather than a dashboard problem.

Of the five core pillars of traditional Governance, Risk, and Compliance (GRC), we deliberately built Jula to attack only two.

### What We Attack (The Revenue Blockers)
We focus exclusively on the two pillars that drain engineering sprint velocity and directly block you from passing audits to close enterprise deals. You don't need another shiny dashboard; you need cryptographic proof of your infrastructure. By programmatically extracting evidence directly from your APIs, we create an "Operational Buffer" that keeps auditors out of your CI/CD pipeline.

1. **IT Risk & Compliance (ITRM):** Mapping technical controls directly to frameworks like SOC 2.
2. **Audit Management:** Programmatically gathering, hashing, and storing cryptographic evidence.

### What We Intentionally Ignore (Bring Your Own Tools)
Why pay a massive premium for redundant software? Traditional GRCs justify $30k+ annual contracts by bundling the remaining three pillars, forcing you to migrate workflows into their proprietary systems. We intentionally leave these out to eliminate software overhead, allowing you to leverage the tools your organization already pays for:

* **Policy Management:** You don't need a specialized SaaS platform to host an Information Security Policy. Write it in Google Workspace, Notion, or Confluence, and use their native version history and access controls.
* **Third-Party Risk (TPRM):** Standardized intake forms routed through existing IT ticketing (Jira/Zendesk) are vastly superior and less noisy than "continuous dark web vendor scanning."
* **Enterprise Risk (ERM):** Formal financial risk modeling is overkill for scaling startups. That risk tracking belongs at the board level.

By pairing this containerized evidence collector with your existing tooling, you eliminate redundant SaaS overhead. Stop wasting time organizing policies in a vendor's portal, and start generating the actual evidence required to pass your audit and close enterprise deals.

---

## Architecture: The Collector-Only Paradigm

Jula uses a **declarative, config-driven** architecture. Instead of writing Go code for every new cloud resource you want to inspect, you simply add a SQL query to a JSON configuration file and the engine handles the rest.

### Multi-Cloud Extraction Engine

The orchestrator dispatches extraction jobs to all configured cloud providers **concurrently** with bounded concurrency. A single run produces a unified evidence set across your entire multi-cloud footprint.

| Provider | Engine | Config File | API |
|---|---|---|---|
| **Google Cloud (GCP)** | `internal/providers/gcp/cai.go` | `configs/extractions/gcp_cai.json` | Cloud Asset Inventory (gRPC) |
| **Amazon Web Services (AWS)** | `internal/providers/aws/config.go` | `configs/extractions/aws_config.json` | AWS Config Advanced Queries (SDK v2) |
| **SaaS & External APIs** | `internal/providers/http_generic/engine.go` | `configs/extractions/saas_http.json` | Universal HTTP Engine (REST/GraphQL) |

### How It Works

1. **Declare:** Define what you want to extract in a JSON config file. Each entry maps an Evidence Request List (ERL) ID to a cloud-native query.
2. **Extract:** The orchestrator loads all provider configs, initializes authenticated clients, and runs every extraction concurrently.
3. **Sign:** Each raw payload is SHA-256 hashed. The hash becomes the filename, guaranteeing immutability and perfect deduplication.
4. **Store:** Evidence files are written to `evidence-output/{date}/evidence/{ERL-ID}/`, namespaced by provider (e.g., `gcp_cai_{hash}.json`, `aws_config_{hash}.json`).
5. **Manifest:** A cryptographically signed `manifest.json` is generated for the entire run, providing tamper-evident proof of collection.

### Immutable Evidence & Cross-Cloud Deduplication

Because filenames are derived from the SHA-256 hash of the raw data and prefixed with the provider name:

- **Multiple clouds, same ERL:** If `E-BCM-16` (Databases) is extracted from both GCP and AWS, both files coexist in the `E-BCM-16/` directory without overwriting each other.
- **Perfect deduplication:** Running the collector 100 times against unchanged infrastructure produces the exact same hash, silently overwriting the same file with identical data.
- **Tamper detection:** If anyone manually modifies an evidence file, the contents will no longer match the filename hash, instantly flagging it as compromised.

## Quick Start

```bash
# Build the Docker image
docker build -t jula-evidence-collector:latest .

# Run with GCP and AWS credentials
docker run --rm \
  -e JULA_GCP_PROJECT_ID="your-project-id" \
  -e JULA_SIGNING_KEY="$JULA_SIGNING_KEY" \
  -e AWS_REGION="us-east-1" \
  -e AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
  -e AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
  -e GOOGLE_APPLICATION_CREDENTIALS=/keys/sa.json \
  -v ./keys:/keys:ro \
  -v ./evidence-output:/evidence-output \
  jula-evidence-collector:latest \
  run -target local -path /evidence-output
```

## Directory Structure

```
jula-evidence-collector/
├── cmd/jula/                  # CLI entrypoint, command parsing, and flag validation.
├── internal/                  # Core domain logic (engine, providers, reporter).
│   ├── engine/                #   Orchestrator: multi-provider concurrent extraction pipeline.
│   ├── providers/             #   Cloud API extractors.
│   │   ├── gcp/               #     GCP Cloud Asset Inventory (CAI) engine.
│   │   ├── aws/               #     AWS Config Advanced Queries engine.
│   │   └── http_generic/      #     Universal HTTP engine for SaaS APIs (GitHub, Aikido, etc).
│   ├── platform/              #   Runtime environment detection (GCP, AWS, Local).
│   └── reporter/              #   Output: local filesystem with signed manifests.
├── pkg/                       # Shared libraries (crypto, types) importable by external tools.
├── configs/                   # Declarative extraction configs.
│   ├── extractions/           #   gcp_cai.json, aws_config.json, saas_http.json
│   └── schemas/oscal/         #   JSON schemas for downstream mapping (Jula EE)
├── keys/                      # Service account credentials (gitignored).
├── evidence-output/           # Generated evidence artifacts (gitignored).
├── Dockerfile                 # Multi-stage build: golang:alpine -> scratch (zero attack surface).
└── LICENSE                    # Business Source License (BSL 1.1).
```

## Adding a New Extraction

No Go code required. Simply add an entry to the appropriate JSON config file.

**Example: Adding an AWS Lambda extraction**

```json
{
  "E-CMP-01": {
    "description": "Lambda Function Configurations",
    "provider": "aws_config",
    "query": "SELECT resourceId, resourceType, configuration, tags WHERE resourceType = 'AWS::Lambda::Function'"
  }
}
```

Rebuild the Docker image and run. The orchestrator will automatically pick up the new ERL and execute it alongside all other extractions.

## Testing

```bash
# Run the orchestrator test suite
docker run --rm -v "$(pwd):/build" -w /build golang:1.25-alpine go test ./internal/engine/... -v
```

The test suite validates:

- **All-success scenarios** (10 concurrent jobs, all return findings)
- **Partial failure resilience** (3 pass, 2 fail, system returns the 3)
- **Total failure abort** (all jobs fail, system returns a descriptive error)
- **Concurrency bounding** (verifies the semaphore never exceeds the configured limit)

## Licensing

This project is licensed under the Business Source License (BSL 1.1). See the [LICENSE](LICENSE) file for details.
