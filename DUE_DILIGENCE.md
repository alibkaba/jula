# Jula Evidence Collector: Due Diligence Review

## 1. Executive Summary

The Jula Evidence Collector is an open-source, CLI-based tool written in Go designed to automate the extraction of infrastructure state for compliance reporting (specifically targeting SOC 2 Type II initially). It positions itself as an "anti-SaaS" alternative, enabling organizations to collect, map, cryptographically sign, and deliver compliance evidence directly to their own cloud storage vaults without relying on expensive, third-party compliance platforms (e.g., Vanta, Drata).

**Maturity Level:** The project is currently in the MVP phase. It supports a limited set of GCP checks, maps to SOC 2, and focuses on core pipeline functionality (Extract -> Map -> Deliver) via a local CLI or containerized execution.

## 2. Technical Architecture Walkthrough

The architecture follows a modular, pipeline-driven approach:

*   **Engine (`internal/engine`):** The `Orchestrator` manages concurrent execution of provider checks, handles context cancellations/timeouts, and applies exceptions from a configuration file.
*   **Providers (`internal/providers`):** Responsible for API authentication and extracting raw infrastructure state. Currently, only GCP is implemented (`internal/providers/gcp`), covering a handful of services (IAM, Cloud Storage, Compute Engine Firewalls, Cloud SQL, Cloud KMS).
*   **Mappers (`internal/mappers`):** Translates raw findings into framework-specific evidence. The MVP supports SOC 2 (`internal/mappers/soc2.go`), evaluating extracted rules against declarative JSON mapping definitions.
*   **Reporters (`internal/reporter`):** Delivers the structured evidence. Supports local file output and Google Cloud Storage (GCS) uploading (`internal/reporter/gcs.go`).
*   **Cryptography (`pkg/crypto`):** Ensures immutability of the generated evidence. After extraction and mapping, an HMAC-SHA256 signature is applied to the final manifest (`pkg/crypto/signing.go`) using an environment-provided key (`JULA_SIGNING_KEY`).

### Execution Flow
The pipeline can run individual steps or the full process via the `run` CLI command:
1.  **Extract:** Queries GCP APIs to gather raw infrastructure findings.
2.  **Map:** Correlates findings to SOC 2 criteria using mapping rules.
3.  **Deliver:** Assembles a `Manifest` containing all evidence, computes an HMAC-SHA256 signature to prevent tampering, and uploads the artifact to the configured storage backend.

## 3. Technical Risks & Limitations

As an MVP, the codebase exhibits several technical limitations and areas requiring maturation before enterprise adoption:

*   **Limited Provider Coverage:** Only Google Cloud Platform (GCP) is currently supported. Multi-cloud environments (AWS, Azure) are not yet implemented.
*   **Shallow GCP Checks:** The GCP provider checks are hardcoded and limited in scope. It currently extracts only 6 specific configurations (e.g., Audit Logging, Storage Encryption, Service Account Key Age). It lacks the comprehensive coverage found in established tools like Steampipe or Cloud Custodian.
*   **Naive Secret Management:** Cryptographic signing relies on an environment variable (`JULA_SIGNING_KEY`). For enterprise deployments (e.g., Cloud Run, ECS), this key must be securely injected via a secrets manager (e.g., GCP Secret Manager, AWS Secrets Manager) rather than plaintext environment variables.
*   **Lack of Policy-as-Code Integration:** The evaluation logic (e.g., checking if a port is prohibited) is hardcoded in Go (`extractors.go`) rather than using a flexible, industry-standard Policy-as-Code engine like Open Policy Agent (OPA/Rego) or CEL. This makes adding or modifying checks rigid and requires a recompile.
*   **Fixed Authentication Mechanisms:** The GCP provider only supports raw JSON keys or Application Default Credentials. More advanced enterprise auth methods (e.g., Workload Identity Federation) are not explicitly handled, though ADC might implicitly support it depending on the deployment environment.

## 4. Business Plan & Go-to-Market Strategy Analysis

The tool's README aggressively positions it against traditional compliance SaaS vendors ("disrupt that model by commoditizing the most complex part... without paying a SaaS middleman").

### Licensing
The project utilizes the **Business Source License (BSL 1.1)**. This is a crucial business decision. BSL is *not* Open Source Initiative (OSI) approved. It allows free use for non-production or limited production use but requires a paid license for broader commercial use (or competing use), eventually converting to an open-source license (usually GPL or Apache) after a set time period (typically 3-4 years).

### Potential Business Strategy ("Open Core" / Monetization)
Given the BSL license and the strong anti-SaaS rhetoric, the likely business model is an **Enterprise Open Core** strategy:

1.  **Commoditize the Base:** Offer the core extraction, mapping, and signing pipeline for free. This builds grassroots adoption among engineering teams frustrated with expensive SaaS implementations.
2.  **Monetize the Enterprise Features (BSL restriction):** Charge for features essential to large organizations. Potential premium features could include:
    *   **Advanced Integrations:** Integrations with JIRA, ServiceNow, or advanced Identity Providers (Okta/Ping).
    *   **Multi-Cloud & Frameworks:** While SOC 2/GCP is free, complex frameworks (PCI-DSS, FedRAMP) or enterprise AWS/Azure support might require a license.
    *   **Managed UI/Dashboard:** The current tool is purely CLI/headless. A premium offering could provide a hosted control plane for auditors to view the generated evidence without digging through raw JSON in an S3 bucket.
    *   **Support & Liability:** Enterprise SLAs and dedicated support channels.

### Business Risks

*   **Auditor Acceptance:** The biggest hurdle is whether external auditors (CPA firms) will accept evidence generated by a self-hosted, newly introduced tool over reports from established, recognized platforms (Vanta, Drata). The cryptographic signing feature is designed to address this, but auditor education and buy-in are required.
*   **Maintenance Burden on Clients:** The pitch "avoid the SaaS middleman" means the client engineering team is now responsible for deploying, maintaining, running, and securing the Jula container. For many organizations, the high cost of compliance SaaS is acceptable because it offloads this operational burden.
*   **Keeping Up with APIs:** Cloud provider APIs and compliance frameworks change constantly. Maintaining the extraction scripts and mapping rules is a massive, ongoing engineering effort. If Jula fails to keep these updated, the tool becomes useless.
*   **Competition from Existing OSS:** The market already has mature open-source infrastructure scanning tools (e.g., CloudSploit, Prowler, Steampipe). Jula must differentiate itself specifically on the *cryptographic signing* and *automated framework mapping* aspects to stand out.