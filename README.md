# Jula Controls

**Programmatic Compliance, Attestation, and Continuous Assurance**

| Component | Build & Release | Description |
| :--- | :--- | :--- |
| **[Collector + Assessor + Core](./collector)** | [![CI/CD: Services](https://github.com/alibkaba/jula/actions/workflows/ci-services.yml/badge.svg)](https://github.com/alibkaba/jula/actions/workflows/ci-services.yml) | Unified build, test, and dual-cloud deploy pipeline |
| **[Governor](./governor)** | [![CI/CD: Governor](https://github.com/alibkaba/jula/actions/workflows/ci-governor.yml/badge.svg)](https://github.com/alibkaba/jula/actions/workflows/ci-governor.yml) | AI translation, policy generation, and bundle signing |
| **[Reporter](./reporter)** | [![CI/CD: Reporter](https://github.com/alibkaba/jula/actions/workflows/ci-reporter.yml/badge.svg)](https://github.com/alibkaba/jula/actions/workflows/ci-reporter.yml) | CLI compliance posture reporting (`jula-posture`) |
| **[Core CLI Tools](./core)** | [![Pipeline: Release](https://github.com/alibkaba/jula/actions/workflows/pipeline-release-artifacts.yml/badge.svg)](https://github.com/alibkaba/jula/actions/workflows/pipeline-release-artifacts.yml) | `jula-sign-evidence` and `jula-verify` standalone binaries |

| Pipeline | Status | Description |
| :--- | :--- | :--- |
| **Canary** | [![Pipeline: Canary](https://github.com/alibkaba/jula/actions/workflows/pipeline-canary.yml/badge.svg)](https://github.com/alibkaba/jula/actions/workflows/pipeline-canary.yml) | Scheduled daily build and integration smoke test |
| **Release** | [![Pipeline: Release](https://github.com/alibkaba/jula/actions/workflows/pipeline-release.yml/badge.svg)](https://github.com/alibkaba/jula/actions/workflows/pipeline-release.yml) | Multi-platform binary release with SLSA attestation |
| **Self-Heal** | [![Pipeline: Self-Heal](https://github.com/alibkaba/jula/actions/workflows/pipeline-self-heal.yml/badge.svg)](https://github.com/alibkaba/jula/actions/workflows/pipeline-self-heal.yml) | AI-driven schema drift remediation |


## The Jula Controls Ecosystem

Jula Controls is a Go workspace of five modules that cooperate to automate security assurance:

* **[Core](./core)** defines shared data models, cryptographic primitives, and three CLI tools: `jula-sign-evidence`, `jula-sign-bundle`, and `jula-verify`.
* **[Collector](./collector)** extracts configurations from cloud APIs and SaaS environments, producing cryptographically signed attestation manifests.
* **[Assessor](./assessor)** verifies evidence signatures, executes OPA Rego policies, and produces signed compliance verdicts (with optional OSCAL output).
* **[Reporter](./reporter)** reads assessment verdicts and renders posture reports via the `jula-posture` CLI: executive summaries, NIST CSF maturity, FAIR risk analysis, ROI visualization, HTML/PDF export, and MCP server integration.
* **[Governor](./governor)** stores Rego policies and uses an AI pipeline to transform compliance catalog prose into machine-executable policy.

Jula treats compliance as an engineering problem rather than a dashboard problem.

## Design Philosophy

Jula is an **assessment integrity engine**, not a GRC platform. It automates a four-stage compliance pipeline:

| Stage | Module | Function |
|:------|:-------|:---------|
| **Translate** | Governor | Compliance catalog prose → executable OPA Rego policy |
| **Collect** | Collector | Cloud/SaaS API configurations → cryptographically signed evidence |
| **Evaluate** | Assessor | Evidence + policy → signed compliance verdicts |
| **Quantify** | Reporter | Verdicts → posture status, maturity scores, FAIR risk analysis |

Every artifact in this pipeline is cryptographically signed. No single key can forge artifacts from another stage.

**What Jula does not cover:** policy document management (use Notion, Confluence), vendor/third-party risk questionnaires (use Jira, Zendesk), and organizational risk registers. These are intentionally excluded to keep the tool focused on the engineering pipeline.

---

## Architecture

Jula operates as a decoupled pipeline, separating evidence attestation, policy evaluation, and posture visualization.

```mermaid
flowchart TB
    %% Styling Classes
    classDef collector fill:#0f172a,stroke:#0ea5e9,stroke-width:2px,color:#e2e8f0;
    classDef ledger fill:#0f172a,stroke:#8b5cf6,stroke-width:2px,color:#e2e8f0;
    classDef policy fill:#0f172a,stroke:#f59e0b,stroke-width:2px,color:#e2e8f0;
    classDef assessor fill:#0f172a,stroke:#10b981,stroke-width:2px,color:#e2e8f0;
    classDef security fill:#1e293b,stroke:#ef4444,stroke-width:1px,color:#f8fafc;
    classDef output fill:#14532d,stroke:#22c55e,stroke-width:2px,color:#f0fdf4;
    classDef insights fill:#0f172a,stroke:#ec4899,stroke-width:2px,color:#e2e8f0;
    classDef core fill:#0f172a,stroke:#94a3b8,stroke-width:2px,color:#e2e8f0;
    classDef trust fill:#1e293b,stroke:#f43f5e,stroke-width:2px,color:#fda4af;

    subgraph Phase1 ["1. Governor Registry (governor/)"]
        direction LR
        Cat["📄 catalog.csv <br> (GRC Controls Catalog)"] -->|AI Extract| Req["📄 requirements.csv <br> (Engineering Requirements Triage)"]
        Req -->|Human Approval & Gen| PR_Pol["📂 policies/rules/ <br> (Generated Core Rego Policies)"]
        PR_Int["📂 engine/integrations/ <br> (YAML Data Collectors)"]
        PR_Norm["📂 engine/translators/ <br> (Rego Payload Adapters)"]
        Meta["📄 workspace.yaml <br> (Active Scopes & Targets)"]
        KeyB["🔑 Key B: Policy Signing <br> (JULA_POLICY_SIGNING_KEY)"] -.->|Sign Bundle| BundleManifest["🛡️ bundle-manifest.json <br> (Signed Policy Bundle)"]
    end

    subgraph Phase2 ["2. Attestation Layer (collector/)"]
        direction TB
        APIs["☁️ Target Provider Scopes <br> (Configured Cloud Service Buckets)"] -->|1. Extract Configs| JIE["Collector Engine <br> (Stateless Go CLI)"]
        JIE -->|2a. Output Payloads| H["📄 Evidence Payloads <br> (Raw JSON / CSV / Text)"]
        KMS["🔑 Key A: Evidence Signing <br> (Cloud KMS Asymmetric Key)"] -.->|Sign Manifest & Prov| Sign["Signing Engine"]
        Sign -->|2b. Sign Provenance| P["🛡️ Provenance Sidecars <br> (*.prov.json)"]
        Sign -->|2c. Sign Manifest| M["📜 Cryptographic Manifest <br> (manifest.json)"]
        Sign -->|2d. Mask & Compress Logs| L["📝 Sanitized Execution Trace <br> (run.log.gz)"]
    end

    subgraph Phase3 ["3. Immutable Attestation Ledger"]
        direction TB
        GCS[("🪣 Secure Object Storage <br> ledger://jula-ledger-{cloud_id} <br> (Versioned + Audit Logged)")]
        H -->|Upload| GCS
        P -->|Upload| GCS
        M -->|Upload| GCS
        L -->|Upload| GCS
    end

    subgraph Phase4 ["4. Continuous Assurance Layer (assessor/)"]
        direction TB
        EE["🔍 Assessor Engine <br> (Stateless Go CLI)"]
        
        subgraph GK ["Gatekeeper Modules"]
            direction LR
            SigCheck["🔑 Manifest Verification <br> (Key A Public)"]
            HashCheck["✅ Integrity Check <br> (Manifest vs Payload Hash)"]
            ProvCheck["🛡️ Provenance Verification <br> (Sidecar Payload Check)"]
            PolicyCheck["🔑 Policy Bundle Verification <br> (Key B Public)"]
        end
        
        OPA["⚙️ Embedded OPA Engine <br> (Dynamic Rego Execution)"]
        KeyC["🔑 Key C: Verdict Signing <br> (JULA_ASSESSOR_SIGNING_KEY)"]
        
        EE --> SigCheck
        SigCheck --> HashCheck
        HashCheck --> ProvCheck
        ProvCheck --> PolicyCheck
        PolicyCheck --> OPA
    end

    subgraph Phase5 ["5. Quantitative Risk & Posture Insights (reporter/)"]
        direction TB
        DB["📊 Posture Reporter <br> (Stateless Go CLI)"]
        
        subgraph Modules ["Modules"]
            direction LR
            Summary["📋 Executive Summary <br> (Control Family Pass/Fail)"]
            Coverage["🔧 Automation Coverage <br> (Auto vs Manual Analysis)"]
            TrendMod["📈 Compliance Trend <br> (Historical Sparklines)"]
            Maturity["🕸️ CSF Maturity <br> (NIST CSF Function Scores)"]
            FAIR["📈 FAIR Risk Analysis <br> (Monte Carlo Simulation)"]
            ROI["📊 Risk ROI <br> (Loss vs Mitigation)"]
            Export["📄 HTML/PDF Export <br> (Executive Report)"]
            MCP["🔌 MCP Server <br> (AI Assistant Integration)"]
        end
        
        DB --> Summary
        DB --> Coverage
        DB --> TrendMod
        DB --> Maturity
        DB --> FAIR
        DB --> ROI
        DB --> Export
        DB --> MCP
    end

    JC["📦 Jula Core <br> (Shared Go Module)"]

    %% Core Data Relationships
    JC -.->|Shared Schema & Crypto| JIE
    JC -.->|Shared Schema & Crypto| EE
    JC -.->|Shared Schema| DB

    %% Governor injections
    PR_Int -->|Remote Streaming| JIE
    Meta -->|--metadata-url Ingestion| EE
    PR_Norm -->|Stream Translators| OPA
    PR_Pol -->|Stream Core Policies| OPA
    BundleManifest -->|Verify Before Load| PolicyCheck

    %% Execution flow
    GCS -->|Pull Signed Ledger Run| SigCheck
    OPA -->|Audit Logs| Findings["🏆 Compliance Findings <br> (assessor_ledger.json + OSCAL AR)"]
    KeyC -.->|Sign Verdict| SignedVerdict["🛡️ Signed Verdict <br> (verdict.json)"]
    Findings --> SignedVerdict
    SignedVerdict -->|Ingest Verified Verdicts| DB

    %% Apply Styles
    class APIs,JIE,H,Sign,P,M,L collector;
    class GCS ledger;
    class PR_Int,PR_Norm,PR_Pol,Meta,BundleManifest policy;
    class EE,SigCheck,HashCheck,ProvCheck,PolicyCheck,OPA assessor;
    class KMS,KeyB,KeyC security;
    class Findings,SignedVerdict output;
    class DB,Summary,Coverage,TrendMod,Maturity,FAIR,Export,ROI,MCP insights;
    class JC core;
```

---

## Zero Trust Architecture

Jula Controls enforces a zero-trust security model across the entire pipeline. No component implicitly trusts another: every artifact is cryptographically signed, verified, and auditable.

### Cryptographic Trust Chain

Three independent ECDSA P-256 signing keys enforce separation of duties:

| Key | Owner | Purpose | Stored As |
|:----|:------|:--------|:----------|
| **Key A** | Collector | Signs evidence manifests and provenance sidecars | Cloud KMS (asymmetric) |
| **Key B** | Governor | Signs policy bundles before Assessor consumption | `JULA_POLICY_SIGNING_KEY` (GitHub Actions secret) |
| **Key C** | Assessor | Signs compliance verdicts after policy evaluation | `JULA_ASSESSOR_SIGNING_KEY` (GitHub Actions secret) |

No single key can forge artifacts from another component. The Assessor verifies Key A signatures on evidence, Key B signatures on policies, and produces Key C signatures on verdicts.

### Supply Chain Integrity

All build artifacts include [SLSA v1.0 provenance attestations](https://slsa.dev) generated by GitHub's first-party `actions/attest-build-provenance` action:

- **Release binaries:** Darwin/ARM64, Linux/AMD64, Windows/AMD64 (Collector, Assessor, jula-sign-evidence, jula-verify)
- **Container images:** GCP Artifact Registry and AWS ECR (Collector + Assessor)

### Evidence Ledger

Evidence is stored in dual-cloud object storage buckets using a consistent naming convention based on cloud account identifiers:

- **Naming:** `jula-ledger-{cloud_id}` where the ID is the AWS Account ID or GCP Project Number
- **Audit logging:** Each ledger has a companion `jula-ledger-audit-{cloud_id}` bucket for access logs
- **Versioning:** Enabled on both clouds to prevent silent overwrites
- **Lifecycle:** Audit logs rotate after 90 days

Jula Controls never receives, stores, or transits raw client infrastructure data. The Collector and Assessor run exclusively inside the client's environment. Only signed compliance verdicts cross the trust boundary.

### Egress Enforcement

The `safehttp` package provides SSRF protection and optional egress allowlisting. When `JULA_EGRESS_ALLOWLIST` is set, only approved domains (cloud provider APIs, GitHub) are reachable. Jula-controlled endpoints are blocked by default.

---

## Licensing

Jula Controls is licensed under the **Business Source License (BSL) 1.1**. See the [LICENSE](./LICENSE) file for full terms.

**Key terms:**

- **Production use is permitted**, including within commercial organizations
- **Attribution required:** All generated artifacts must retain "Powered by Jula Controls" visible to the end consumer
- **Rolling Change Date:** Each release converts to Apache License 2.0 four years after publication
- **Expressly prohibited** without an Enterprise License:
  - (a) Use by consultants, MSSPs, or vCISOs to deliver commercial compliance services to their own clients
  - (b) Hosting as a managed service or embedding in a competing commercial SaaS/API product
  - (c) Use as training data for AI/ML models or automated code generation tools

For Enterprise License inquiries, contact the Licensor.

