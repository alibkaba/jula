# Jula Core

**Programmatic Compliance, Attestation, and Continuous Assurance**

| Component | Build & Release | Quality & Tech | License |
| :--- | :--- | :--- | :--- |
| **[Jula Core](https://github.com/alibkaba/jula-core)** | [![CI/CD Pipeline](https://github.com/alibkaba/jula-core/actions/workflows/main.yml/badge.svg)](https://github.com/alibkaba/jula-core/actions/workflows/main.yml) <br> [![GitHub Release](https://img.shields.io/github/v/release/alibkaba/jula-core?color=blue&logo=github)](https://github.com/alibkaba/jula-core/releases) | [![Go Version](https://img.shields.io/github/go-mod/go-version/alibkaba/jula-core?logo=go)](https://go.dev/) <br> [![Go Report Card](https://goreportcard.com/badge/github.com/alibkaba/jula-core)](https://goreportcard.com/report/github.com/alibkaba/jula-core) | [![License](https://img.shields.io/badge/License-BSL_1.1-orange.svg)](LICENSE) |
| **[Jula Evidence Collector](https://github.com/alibkaba/jula-evidence-collector)** | [![CI/CD Pipeline](https://github.com/alibkaba/jula-evidence-collector/actions/workflows/main.yml/badge.svg)](https://github.com/alibkaba/jula-evidence-collector/actions/workflows/main.yml) <br> [![GitHub Release](https://img.shields.io/github/v/release/alibkaba/jula-evidence-collector?color=blue&logo=github)](https://github.com/alibkaba/jula-evidence-collector/releases) | [![Go Version](https://img.shields.io/github/go-mod/go-version/alibkaba/jula-evidence-collector?logo=go)](https://go.dev/) <br> [![Go Report Card](https://goreportcard.com/badge/github.com/alibkaba/jula-evidence-collector)](https://goreportcard.com/report/github.com/alibkaba/jula-evidence-collector) | [![License](https://img.shields.io/badge/License-BSL_1.1-orange.svg)](LICENSE) |
| **[Jula Evidence Evaluator](https://github.com/alibkaba/jula-evidence-evaluator)** | [![CI/CD Pipeline](https://github.com/alibkaba/jula-evidence-evaluator/actions/workflows/main.yml/badge.svg)](https://github.com/alibkaba/jula-evidence-evaluator/actions/workflows/main.yml) <br> [![GitHub Release](https://img.shields.io/github/v/release/alibkaba/jula-evidence-evaluator?color=blue&logo=github)](https://github.com/alibkaba/jula-evidence-evaluator/releases) | [![Go Version](https://img.shields.io/github/go-mod/go-version/alibkaba/jula-evidence-evaluator?logo=go)](https://go.dev/) <br> [![Go Report Card](https://goreportcard.com/badge/github.com/alibkaba/jula-evidence-evaluator)](https://goreportcard.com/report/github.com/alibkaba/jula-evidence-evaluator) | [![License](https://img.shields.io/badge/License-BSL_1.1-orange.svg)](LICENSE) |
| **[Jula Compliance Policies](https://github.com/alibkaba/jula-compliance-policies)** | N/A | [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) <br> Versioned Rego Rules | [![License](https://img.shields.io/badge/License-BSL_1.1-orange.svg)](LICENSE) |

## The Jula Controls Ecosystem

Jula Controls is designed as a decoupled, multi-repository architecture where specialized tools cooperate to automate security assurance:

* The **[Jula Evidence Collector](https://github.com/alibkaba/jula-evidence-collector) extracts configurations** programmatically from cloud APIs and SaaS environments, producing cryptographically signed attestation manifests and raw JSON evidence.
* The **[Jula Evidence Evaluator](https://github.com/alibkaba/jula-evidence-evaluator) evaluates compliance** by consuming those signed manifests, validating their signature, and executing OPA rules against the ingested payloads to generate audit findings.
* The **[Jula Compliance Policies](https://github.com/alibkaba/jula-compliance-policies) stores Rego policies** in a version-controlled repository that serves as the single source of truth for the evaluation logic.
* The **[Jula Core](https://github.com/alibkaba/jula-core) defines shared models and cryptographic validation** utilities used by all modules, ensuring consistent data schemas across the pipeline.

---

## Jula Core Package Structure

Jula Core (`github.com/alibkaba/jula-core`) contains the shared data structures and cryptographic libraries used by the Jula Continuous Compliance pipeline.

* The **`pkg/types` package defines shared models** for findings, evidence, and manifest files.
* The **`pkg/crypto` package implements ECDSA signature methods** for signing and verifying manifests and provenance sidecars.
