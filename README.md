# Jula Controls

**Programmatic Compliance, Attestation, and Continuous Assurance**

| Component | Build & Release | Description |
| :--- | :--- | :--- |
| **[Jula Core](./core)** | [![CI/CD Pipeline](https://github.com/alibkaba/jula/actions/workflows/ci-core.yml/badge.svg)](https://github.com/alibkaba/jula/actions/workflows/ci-core.yml) | Shared models and cryptographic utilities |
| **[Jula Collector](./collector)** | [![CI/CD Pipeline](https://github.com/alibkaba/jula/actions/workflows/ci-collector.yml/badge.svg)](https://github.com/alibkaba/jula/actions/workflows/ci-collector.yml) | Stateless Go extraction engine |
| **[Jula Evaluator](./evaluator)** | [![CI/CD Pipeline](https://github.com/alibkaba/jula/actions/workflows/ci-evaluator.yml/badge.svg)](https://github.com/alibkaba/jula/actions/workflows/ci-evaluator.yml) | Policy evaluation and manifest verification |
| **[Jula Governor](./governor)** | [![CI/CD Pipeline](https://github.com/alibkaba/jula/actions/workflows/ci-governor.yml/badge.svg)](https://github.com/alibkaba/jula/actions/workflows/ci-governor.yml) | AI Translation & Policy Generation CLI |

## The Jula Controls Ecosystem

Jula Controls is designed as a decoupled, multi-repository architecture (now consolidated into a monorepo) where specialized tools cooperate to automate security assurance:

* The **[Jula Core](./core) defines shared models and cryptographic validation** utilities used by all modules, ensuring consistent data schemas across the pipeline.
* The **[Jula Collector](./collector) extracts configurations** programmatically from cloud APIs and SaaS environments, producing cryptographically signed attestation manifests and raw JSON evidence blobs. The Collector is an ultra-lightweight, stateless network engine running entirely on native Go standard network primitives (`net/http`). Both Cloud hyperscalers and SaaS targets are now defined as pure-text configurations, with cloud targets dynamically authenticated at the edge via the compiled **Frozen Signer Module**.
* The **[Jula Evaluator](./evaluator) evaluates compliance** by consuming those raw artifacts, verifying manifest and provenance signatures, ingesting client configuration metadata, and executing dynamic OPA policies.
* The **[Jula Governor](./governor) stores Rego policies** in a version-controlled directory that serves as the single source of truth for both dynamic resource normalization and compliance scoping rules.

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
* For **enterprise risk management**, formal financial risk modeling is overkill for velocity-driven engineering organizations since that risk tracking belongs at the board level.

By pairing this containerized evidence suite with your existing tooling, you eliminate redundant SaaS overhead. Stop wasting time organizing policies in a vendor's portal, and start generating the actual evidence required to pass your audit and close enterprise deals.

---

## Decoupled Architecture: The Attestation & Assurance Paradigm

Jula Controls operates as a decoupled pipeline, cleanly separating raw evidence attestation, governor evaluation, and executive posture visualization.

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

    subgraph Phase1 ["1. Governor Registry (governor/)"]
        direction LR
        Cat["📄 catalog.csv <br> (GRC Controls Catalog)"] -->|AI Extract| Req["📄 requirements.csv <br> (Engineering Requirements Triage)"]
        Req -->|Human Approval & Gen| PR_Pol["📂 policies/rules/ <br> (Generated Core Rego Policies)"]
        PR_Int["📂 engine/integrations/ <br> (YAML Data Collectors)"]
        PR_Norm["📂 engine/translators/ <br> (Rego Payload Adapters)"]
        Meta["📄 workspace.yaml <br> (Active Scopes & Targets)"]
    end

    subgraph Phase2 ["2. Attestation Layer (collector/)"]
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

    subgraph Phase4 ["4. Continuous Assurance Layer (evaluator/)"]
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

    %% Governor injections
    PR_Int -->|Remote Streaming| JIE
    Meta -->|--metadata-url Ingestion| EE
    PR_Norm -->|Stream Translators| OPA
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

---

## Licensing

Jula Controls is licensed under the **Business Source License (BSL) 1.1**. See the [LICENSE](./LICENSE) file for full terms.

**Key terms:**

- **Internal, non-commercial use** is permitted with attribution ("Powered by Jula Controls")
- **Rolling Change Date:** Each release converts to Apache License 2.0 four years after publication
- **Expressly prohibited** without an Enterprise License:
  - (a) Use by consultants, MSSPs, or vCISOs to deliver commercial compliance services
  - (b) Hosting as a managed service or embedding in a commercial SaaS/API product
  - (c) Use as training data for AI/ML models or automated code generation tools

For Enterprise License inquiries, contact the Licensor.

