# Jula Controls

**Programmatic Compliance, Attestation, and Continuous Assurance**

| Component | Build & Release | Quality & Tech | License |
| :--- | :--- | :--- | :--- |
| **[Jula Core](https://github.com/alibkaba/jula-core)** | [![CI/CD Pipeline](https://github.com/alibkaba/jula-core/actions/workflows/main.yml/badge.svg)](https://github.com/alibkaba/jula-core/actions/workflows/main.yml) <br> [![GitHub Release](https://img.shields.io/github/v/release/alibkaba/jula-core?color=blue&logo=github)](https://github.com/alibkaba/jula-core/releases) | [![Go Version](https://img.shields.io/github/go-mod/go-version/alibkaba/jula-core?logo=go)](https://go.dev/) <br> [![Go Report Card](https://goreportcard.com/badge/github.com/alibkaba/jula-core)](https://goreportcard.com/report/github.com/alibkaba/jula-core) | [![License](https://img.shields.io/badge/License-BSL_1.1-orange.svg)](LICENSE) |
| **[Jula Collector](https://github.com/alibkaba/jula-collector)** | [![CI/CD Pipeline](https://github.com/alibkaba/jula-collector/actions/workflows/main.yml/badge.svg)](https://github.com/alibkaba/jula-collector/actions/workflows/main.yml) <br> [![GitHub Release](https://img.shields.io/github/v/release/alibkaba/jula-collector?color=blue&logo=github)](https://github.com/alibkaba/jula-collector/releases) | [![Go Version](https://img.shields.io/github/go-mod/go-version/alibkaba/jula-collector?logo=go)](https://go.dev/) <br> [![Go Report Card](https://goreportcard.com/badge/github.com/alibkaba/jula-collector)](https://goreportcard.com/report/github.com/alibkaba/jula-collector) | [![License](https://img.shields.io/badge/License-BSL_1.1-orange.svg)](LICENSE) |
| **[Jula Evaluator](https://github.com/alibkaba/jula-evaluator)** | [![CI/CD Pipeline](https://github.com/alibkaba/jula-evaluator/actions/workflows/main.yml/badge.svg)](https://github.com/alibkaba/jula-evaluator/actions/workflows/main.yml) <br> [![GitHub Release](https://img.shields.io/github/v/release/alibkaba/jula-evaluator?color=blue&logo=github)](https://github.com/alibkaba/jula-evaluator/releases) | [![Go Version](https://img.shields.io/github/go-mod/go-version/alibkaba/jula-evaluator?logo=go)](https://go.dev/) <br> [![Go Report Card](https://goreportcard.com/badge/github.com/alibkaba/jula-evaluator)](https://goreportcard.com/report/github.com/alibkaba/jula-evaluator) | [![License](https://img.shields.io/badge/License-BSL_1.1-orange.svg)](LICENSE) |
| **[Jula Compliance-as-Code](https://github.com/alibkaba/jula-compliance-as-code)** | N/A | [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) <br> Versioned Rego Rules | [![License](https://img.shields.io/badge/License-BSL_1.1-orange.svg)](LICENSE) |

## The Jula Controls Ecosystem

Jula Controls is designed as a decoupled, multi-repository architecture where specialized tools cooperate to automate security assurance:

* The **[Jula Collector](https://github.com/alibkaba/jula-collector) extracts configurations** programmatically from cloud APIs and SaaS environments, producing cryptographically signed attestation manifests and raw JSON evidence blobs. The Collector is an ultra-lightweight, stateless network engine running entirely on native Go standard network primitives (`net/http`). Both Cloud hyperscalers and SaaS targets are now defined as pure-text configurations, with cloud targets dynamically authenticated at the edge via the compiled **Frozen Signer Module**.
* The **[Jula Evaluator](https://github.com/alibkaba/jula-evaluator) evaluates compliance** by consuming those raw artifacts, verifying manifest and provenance signatures, ingesting client configuration metadata, and executing dynamic OPA policies.
* The **[Jula Compliance-as-Code](https://github.com/alibkaba/jula-compliance-as-code) stores Rego policies** in a version-controlled repository that serves as the single source of truth for both dynamic resource normalization and compliance scoping rules.

Traditional compliance platforms charge massive premiums for monolithic dashboards, forcing you to adopt heavy, misaligned workflows and endpoint agents. **Jula Controls** is designed to disrupt that model by treating compliance as an engineering problem rather than a dashboard problem.

## The Philosophy: Attestation Engineering vs. Traditional GRC

Of the five core pillars of traditional Governance, Risk, and Compliance (GRC), Jula Controls attacks only two: IT Risk & Compliance (ITRM) and Audit Management.

### What We Attack (The Revenue Blockers)
We focus exclusively on the two pillars that drain engineering sprint velocity and directly block you from passing audits to close enterprise deals. You do not need another shiny dashboard; you need cryptographic proof of your infrastructure. By programmatically extracting evidence directly from your APIs, we create an operational buffer that keeps auditors out of your CI/CD pipeline.

1. **IT Risk & Compliance (ITRM):** Mapping technical controls directly to framework specifications via decoupled, dynamic policy logic.
2. **Audit Management:** Programmatically gathering, hashing, and storing cryptographic evidence.

### What We Intentionally Ignore (Bring Your Own Tools)
Why pay a massive premium for redundant software? Traditional GRCs justify heavy annual contracts by bundling the remaining three pillars, forcing you to migrate workflows into their proprietary systems. We intentionally leave these out to eliminate software overhead, allowing you to leverage the tools your organization already pays for:

* For **policy management**, you do not need a specialized SaaS platform to host an Information Security Policy. Write it in Google Workspace, Notion, or Confluence, and use their native version history and access controls.
* For **third-party risk management**, standardized intake forms routed through existing IT ticketing (Jira or Zendesk) are vastly superior and less noisy than third-party scanning portals.
* For **enterprise risk management**, formal financial risk modeling is overkill for scaling startups since that risk tracking belongs at the board level.

By pairing this containerized evidence suite with your existing tooling, you eliminate redundant SaaS overhead. Stop wasting time organizing policies in a vendor's portal, and start generating the actual evidence required to pass your audit and close enterprise deals.

---

## Decoupled Architecture: The Attestation & Assurance Paradigm

Jula Controls operates as a decoupled pipeline, cleanly separating raw evidence attestation, compliance-as-code evaluation, and executive posture visualization.

```mermaid
flowchart TB
    %% Styling Classes
    classDef collector fill:#0f172a,stroke:#0ea5e9,stroke-width:2px,color:#e2e8f0;
    classDef ledger fill:#0f172a,stroke:#8b5cf6,stroke-width:2px,color:#e2e8f0;
    classDef policy fill:#0f172a,stroke:#f59e0b,stroke-width:2px,color:#e2e8f0;
    classDef evaluator fill:#0f172a,stroke:#10b981,stroke-width:2px,color:#e2e8f0;
    classDef security fill:#1e293b,stroke:#ef4444,stroke-width:1px,color:#f8fafc;
    classDef output fill:#14532d,stroke:#22c55e,stroke-width:2px,color:#f0fdf4;
    classDef insights fill:#0f172a,stroke:#ec4899,stroke-width:2px,color:#e2e8f0;
    classDef core fill:#0f172a,stroke:#94a3b8,stroke-width:2px,color:#e2e8f0;

    subgraph Phase1 ["1. Compliance-as-Code Registry (jula-compliance-as-code)"]
        direction LR
        Cat["📄 catalog.csv <br> (GRC Controls Catalog)"] -->|AI Extract| Req["📄 requirements.csv <br> (Engineering Requirements Triage)"]
        Req -->|Human Approval & Gen| PR_Pol["📂 policies/rules/ <br> (Generated Core Rego Policies)"]
        PR_Int["📂 engine/integrations/ <br> (YAML Data Collectors)"]
        PR_Norm["📂 engine/normalizers/ <br> (Rego Payload Adapters)"]
        Meta["📄 workspace.yaml <br> (Active Scopes & Targets)"]
    end

    subgraph Phase2 ["2. Attestation Layer (Jula Collector)"]
        direction TB
        APIs["☁️ Target Provider Scopes <br> (Configured Cloud Service Buckets)"] -->|1. Extract Configs| JIE["Collector Engine <br> (Stateless Go CLI)"]
        JIE -->|2a. Output Payloads| H["📄 Evidence Payloads <br> (Raw JSON / CSV / Text)"]
        KMS["🔑 Cloud Secret Manager / Key Vault <br> (Asymmetric Private Key)"] -.->|Sign Manifest & Prov| Sign["Signing Engine"]
        Sign -->|2b. Sign Provenance| P["🛡️ Provenance Sidecars <br> (*.prov.json)"]
        Sign -->|2c. Sign Manifest| M["📜 Cryptographic Manifest <br> (manifest.json)"]
        Sign -->|2d. Mask & Compress Logs| L["📝 Sanitized Execution Trace <br> (run.log.gz)"]
    end

    subgraph Phase3 ["3. Attestation Ledger"]
        direction TB
        GCS[("🪣 Secure Object Storage <br> ledger://jula-evidence-ledger <br> (Uniform Bucket Access Enabled)")]
        H -->|Upload| GCS
        P -->|Upload| GCS
        M -->|Upload| GCS
        L -->|Upload| GCS
    end

    subgraph Phase4 ["4. Continuous Assurance Layer (Jula Evaluator)"]
        direction TB
        EE["🔍 Evaluator Engine <br> (Stateless Go CLI)"]
        
        subgraph GK ["Gatekeeper Modules"]
            direction LR
            SigCheck["🔑 Signature Verification <br> (JULA_PUBLIC_KEY PEM)"]
            HashCheck["✅ Integrity Check <br> (Manifest vs Payload Hash)"]
            ProvCheck["🛡️ Provenance Verification <br> (Sidecar Payload Check)"]
        end
        
        OPA["⚙️ Embedded OPA Engine <br> (Dynamic Rego Execution)"]
        
        EE --> SigCheck
        SigCheck --> HashCheck
        HashCheck --> ProvCheck
        ProvCheck --> OPA
    end

    subgraph Phase5 ["5. Quantitative Risk & Posture Insights (Jula Insight Engine)"]
        direction TB
        DB["📊 Insight Engine <br> (Quantitative Risk & Posture)"]
        
        subgraph Views ["Visualization Modules"]
            direction LR
            LEC["📈 Loss Exceedance Curve <br> (FAIR Financial Simulation)"]
            Radar["🕸️ Maturity Radar Chart <br> (NIST CSF spider chart)"]
            ROI["📊 Risk ROI Bar Chart <br> (Mitigation Cost vs Residual Loss)"]
            Trend["📈 KRI Trend Lines <br> (12-Month Maturity Tracking)"]
        end
        
        DB --> LEC
        DB --> Radar
        DB --> ROI
        DB --> Trend
    end

    JC["📦 Jula Core <br> (Shared Go Module)"]

    %% Core Data Relationships
    JC -.->|Shared Schema & Crypto| JIE
    JC -.->|Shared Schema & Crypto| EE
    JC -.->|Shared Schema| DB

    %% Compliance-as-Code injections
    PR_Int -->|Remote Streaming| JIE
    Meta -->|--metadata-url Ingestion| EE
    PR_Norm -->|Stream Normalizers| OPA
    PR_Pol -->|Stream Core Policies| OPA

    %% Execution flow
    GCS -->|Pull Signed Ledger Run| SigCheck
    OPA -->|Audit Logs| Findings["🏆 Standardized Findings Ledger <br> (OSCAL Assessment Results)"]
    Findings -->|Ingest Findings JSON| DB

    %% Apply Styles
    class APIs,JIE,H,Sign,P,M,L collector;
    class GCS ledger;
    class PR_Int,PR_Norm,PR_Pol,Meta policy;
    class EE,SigCheck,HashCheck,ProvCheck,OPA evaluator;
    class KMS security;
    class Findings output;
    class DB,LEC,Radar,ROI,Trend insights;
    class JC core;
```

### 1. [Jula Compliance-as-Code](https://github.com/alibkaba/jula-compliance-as-code) (The Compliance-as-Code Registry)

The Compliance-as-Code Registry houses version-controlled compliance libraries written in Open Policy Agent (OPA) Rego language. This serves as the single source of truth for both structural data normalization (mapping cloud-specific parameters to agnostic target schemas on the fly) and scoping/applicability rule validation.

### 2. [Jula Collector](https://github.com/alibkaba/jula-collector) (The Attestation & Extraction Engine)

The Collector programmatically extracts configurations from active Target Provider Scopes, producing cryptographically signed attestation manifests and raw JSON evidence blobs. The Collector runs a stateless Collector Engine built entirely on native Go primitives.

### 3. [Jula Evaluator](https://github.com/alibkaba/jula-evaluator) (The Assurance Engine)

The Evaluator evaluates compliance by running a stateless Evaluator Engine that consumes those raw ledger artifacts, verifies manifest signatures, and executes dynamic OPA scoping and verification rules.

### 4. [Jula Core](https://github.com/alibkaba/jula-core) (The Shared Go Library)

The Shared Go Library houses the shared data structures (Finding, Evidence, Manifest) and cryptographic signature signing/verification utilities used across the Jula Attestation and Assurance engines.

### 5. Jula Insight Engine (Future Analytical Layer)

The future Jula Insight Engine will ingest the OSCAL Assessment Results generated by the Jula Evaluator to translate technical security findings into operational maturity tracking and quantitative financial risk metrics for board-level reporting.

---

## The Continuous Compliance Pipeline

1. **Declare:** Define what you want to extract in declarative YAML configuration files. Cloud and SaaS integrations are defined using OpenAPI-inspired YAML integrations mapped to target Evidence IDs.

2. **Extract & Hash:** The Collector runs queries concurrently. Raw unmodified payloads are saved as `{evidence_id}_{provider}_{source_id}.json`. The raw payload is SHA-256 hashed to produce the payload hash.

3. **Sign & Attest:** The Collector generates an ECDSA-signed provenance sidecar (`.prov.json`) for each finding containing the payload hash. It compiles all hashes and the execution trace log (`run.log.gz`) hash into a unified manifest (`manifest.json`) and signs it to generate a cryptographically verifiable attestation of the run.

4. **Verify & Evaluate:** The Evaluator verifies the manifest and provenance signatures using the public key. It indexes raw payloads into an evaluation matrix structured under `input.findings[evidence_id][source_id]` and loads customer Statement of Applicability details via `--metadata-url`. It passes this data map to the dynamic Rego helper libraries for normalization and compliance check rule verification.

5. **Analyze & Simulate:** The Jula Insights engine models enterprise risk exposure and posture maturity using quantitative FAIR simulations and NIST CSF radar maps.

---

## Flag & Configuration Usage

The engine supports robust configuration scoping via local directories or remote stream injections.
- **Local Directory:** Use the `JULA_INTEGRATION_DIR` environment variable (or `--integration-dir` CLI flag), which defaults to `"integrations"`. The engine traverses `integrations/universal_cloud/` and `integrations/universal_rest/` to parse targets.
- **Remote Streaming:** Use the `--integration-url` flag (or `JULA_INTEGRATION_URL` environment fallback) to pass a remote target. The engine fetches an `integrations.tar.gz` archive, decompresses it natively via `compress/gzip` and `archive/tar`, and inflates the configurations directly into a thread-safe in-memory map for scratch-container execution without ever touching the disk.

## Declarative & Integration-Driven Configurations

Jula Controls uses a config-driven schema. Adding new resource checks requires zero Go code changes. You simply add a query or REST specification to a configuration file:

* Cloud hyperscalers and SaaS targets are both defined via text-based YAML integrations.
* They map REST configurations using OpenAPI-inspired schemas specifying auth flows like `aws_sigv4`, `gcp_adc`, `oauth2`, or `bearer`.
* Support pagination cursors, header schemas, and Evidence ID mappings. Virtual query parameters (`jula_evidence=`) are automatically supported to permit mapping a single physical endpoint across multiple unique integration registry keys.

### Configuration Example (Cloud POST-Driven Integration)

```yaml
vendor_name: "aws"
provider: "aws"
auth_flow:
  type: "aws_sigv4"
endpoints:
  "https://config.${AWS_REGION}.amazonaws.com/":
    method: "POST"
    evidence_id: "EVID-IAM-01"
    description: "Query IAM Users via AWS Config REST gateway"
    body:
      Expression: "SELECT resourceId WHERE resourceType = 'AWS::IAM::User'"
```

---

## Pipeline Validation & Self-Healing Automation

We maintain an automated continuous assurance loop that validates pipeline integrity. If a scheduled canary run fails due to schema variations, our integrated autonomous agent triggers to patch Rego normalizer mapping libraries on the fly.

To trigger an air-gapped E2E validation tracer test locally:
```bash
./automation/autonomous_heal.sh
```

---

## Roadmap

The current ecosystem provides a robust, decoupled architecture for continuous compliance, but deploying it requires manual setup. Upcoming roadmap priorities focus on simplifying the adoption and operational overhead of the Jula suite:

* **[ ] IaC Deployment Templates:** Create unified Infrastructure as Code (IaC) deployment packages (e.g., Terraform modules, AWS CloudFormation templates, Azure Resource Manager templates, or GCP Deployment Manager manifests) to allow users to spin up the entire Collector and Evaluator pipeline with a single command.

---

## Licensing

Jula Controls is licensed under the Business Source License (BSL 1.1). See the `LICENSE` file for details.