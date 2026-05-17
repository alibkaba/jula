# Jula Evidence Evaluator

The Jula Evidence Evaluator is a high-performance compliance evaluation engine designed to ingest raw system evidence payloads and systematically assess them against standardized Secure Controls Framework (SCF) controls and OSCAL assessment plans.

Working in lockstep with the [Jula Evidence Collector](https://github.com/alibkaba/jula-evidence-collector), the evaluator automates zero-trust control auditing, schema validation, and objective GRC mapping.

## Key Features

- **OSCAL Assessment Plan Matching:** Automatically validates collected payloads against the canonical GRC schemas.
- **Secure Controls Framework Alignment:** Translates raw infrastructure configurations into concrete SCF compliance findings.
- **Declarative Rule Evaluations:** Evaluates evidence from SaaS HTTP, AWS Config SQL queries, and GCP CAI resources using flexible rules.
- **Stunning Audit Reporting:** Outputs machine-readable GRC report payloads compatible with automatic compliance dashboards.

## Getting Started

### Prerequisites

- Go >= 1.25.0
- Docker (for isolated, containerized execution)

### Installation

```bash
git clone https://github.com/alibkaba/jula-evidence-evaluator.git
cd jula-evidence-evaluator
go mod download
```
