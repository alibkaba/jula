# Jula Evidence Collector

**Primary Language:** Go (Golang)

A high-performance, open-source CLI tool that programmatically extracts infrastructure state to generate continuous compliance telemetry. 

## Zero-Friction Compliance

Modern compliance platforms charge massive premiums for onboarding, API mapping, and implementation. The **Jula Evidence Collector** is designed to disrupt that model by commoditizing the most complex part of compliance: automated, cryptographically signed evidence gathering.

By pairing this containerized evidence collector with standard document management and ticketing tools, engineering teams can achieve SOC 2 compliance (with additional frameworks planned for the future) without paying a SaaS middleman, enduring lengthy implementations, or accepting vendor lock-in.

## Quick Start
```bash
go run cmd/jula/main.go
```

## Architecture

1. **The Core Engine:** Handles CLI execution, concurrent Go routines, logging, and JSON report generation.
2. **The Providers:** Isolated modules that handle API authentication and state extraction.
3. **The Mappers:** Configuration files that map the raw telemetry from Providers to specific compliance frameworks.
4. **The Reporters:** Deliver signed, cryptographically verifiable evidence directly to the client's own cloud storage vault (S3, GCS, Azure Blob), giving auditors direct access without a SaaS middleman.
5. **Cloud Agnosticism:** Compiles to a standard Docker container capable of executing natively in AWS (ECS Fargate), GCP (Cloud Run), or Azure (Container Instances).
## Licensing
This project is licensed under the Business Source License (BSL 1.1). See the [LICENSE](LICENSE) file for details.
