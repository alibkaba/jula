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
    %% ══════════════════════════════════════════════════
    %% 🎨 Color System: Themed Boundaries & High-Contrast Nodes
    %%   🟠 Governor  = Peach / Orange  (Policy Auth)
    %%   🔵 Collector = Light Blue      (Ingestion)
    %%   ⚪ Ledger    = Cool Gray       (Data at Rest)
    %%   🟢 Assessor  = Light Green     (Evaluation Engine)
    %%   🟣 Reporter  = Light Purple    (Visualization Engine)
    %%   ⬛ Core      = Dark Zinc       (Shared Low-Level Utilities)
    %%   🌹 Data      = Rose            (Intermediate Artifacts)
    %%   🔷 Output    = Cyan            (Final Deliverables)
    %%   🔑 Keys      = Owner-tinted    (Crypto Primitives, 3px stroke)
    %%   ✅ Verify    = Mid-tone        (Check-gate Bridges, 3px stroke)
    %% ══════════════════════════════════════════════════

    %% 🏗️ Module Node Styles
    classDef governor fill:#ffebd8,stroke:#ea580c,stroke-width:2px,color:#431407,font-family:system-ui,sans-serif;
    classDef collector fill:#eff6ff,stroke:#2563eb,stroke-width:2px,color:#1e3a8a,font-family:system-ui,sans-serif;
    classDef assessor fill:#f0fdf4,stroke:#16a34a,stroke-width:2px,color:#14532d,font-family:system-ui,sans-serif;
    classDef reporter fill:#faf5ff,stroke:#7c3aed,stroke-width:2px,color:#581c87,font-family:system-ui,sans-serif;
    classDef ledger fill:#f8fafc,stroke:#64748b,stroke-width:2px,color:#0f172a,font-family:system-ui,sans-serif;
    classDef core fill:#f4f4f5,stroke:#27272a,stroke-width:2px,color:#09090b,font-family:system-ui,sans-serif;
 
    %% 📦 Data / Deliverable Artifact Styles (Separated from Engines)
    classDef dataBundle fill:#fff1f2,stroke:#f43f5e,stroke-width:2px,color:#4c0519,font-family:system-ui,sans-serif;
    classDef finalOutput fill:#ecfeff,stroke:#0891b2,stroke-width:2px,color:#164e63,font-family:system-ui,sans-serif;
 
    %% 🔑 Cryptographic Key Primitives (owner-tinted, thick border)
    classDef keyA fill:#eff6ff,stroke:#2563eb,stroke-width:3px,color:#1e3a8a,font-family:system-ui,sans-serif;
    classDef keyB fill:#ffebd8,stroke:#ea580c,stroke-width:3px,color:#431407,font-family:system-ui,sans-serif;
    classDef keyC fill:#f0fdf4,stroke:#16a34a,stroke-width:3px,color:#14532d,font-family:system-ui,sans-serif;
 
    %% ✅ Verification Check-gates
    classDef verifyA fill:#eff6ff,stroke:#2563eb,stroke-width:3px,color:#1e3a8a,font-family:system-ui,sans-serif;
    classDef verifyB fill:#ffebd8,stroke:#ea580c,stroke-width:3px,color:#431407,font-family:system-ui,sans-serif;
    classDef verifyC fill:#f0fdf4,stroke:#16a34a,stroke-width:3px,color:#14532d,font-family:system-ui,sans-serif;
    classDef verifyInteg fill:#ccfbf1,stroke:#0d9488,stroke-width:1.5px,color:#115e59,font-family:system-ui,sans-serif;

    subgraph ClientLocal ["💻 Client Local & GitOps Space"]
        direction TB

        subgraph Phase1 ["1. Governor Registry (governor/)"]
            direction LR
            Cat["📄 catalog.csv<br>(GRC Controls Catalog)"] -->|AI Extract| Req["📄 requirements.csv<br>(Engineering Requirements)"]
            Req -->|Approve + Generate| PR_Pol["📂 policies/rules/<br>(Rego Policies)"]
            PR_Int["📂 engine/integrations/<br>(YAML Data Collectors)"]
            PR_Norm["📂 engine/translators/<br>(Rego Payload Adapters)"]
            Meta["📄 workspace.yaml<br>(Active Scopes)"]
            KeyB["🔑 Key B: Policy Signing<br>(JULA_POLICY_SIGNING_KEY)"] -.->|Sign Bundle| BundleManifest["🛡️ bundle-manifest.json<br>(Signed Policy Bundle)"]
        end

        subgraph Phase5 ["5. Posture Insights (reporter/) 🚧"]
            direction TB
            VerdictGate["✅ Verdict Verify<br>(Key C Public)"]
            DB["📊 Posture Reporter<br>(jula-posture CLI)"]

            subgraph Analysis ["Analysis"]
                direction LR
                Summary["📋 Executive Summary"]
                Coverage["🔧 Automation Coverage"]
                TrendMod["📈 Compliance Trend"]
                Maturity["🕸️ CSF Maturity"]
            end

            subgraph Risk ["Risk Quantification"]
                direction LR
                FAIR["📈 FAIR Monte Carlo"]
                ROI["📊 Risk vs Mitigation ROI"]
            end

            subgraph Output ["Output"]
                direction LR
                Export["📄 HTML / PDF Export"]
                MCP["🔌 MCP Server"]
            end

            VerdictGate --> DB
            DB --> Analysis
            DB --> Risk
            DB --> Output
        end

        JC["📦 Jula Core<br>(Shared Go Module)"]
    end

    subgraph ClientCloud ["☁️ Client Cloud Infrastructure (AWS / GCP)"]
        direction LR

        subgraph TargetEnv ["☁️ Target Environment (Production, Staging, etc.)"]
            direction LR
            APIs["☁️ Target Provider Scopes<br>(AWS, GCP, SaaS APIs)"]
        end

        subgraph ComplianceEnv ["🔒 Dedicated Compliance Account / Project (Isolated VPC)"]
            direction TB

            subgraph Phase2 ["2. Attestation Layer (collector/)"]
                direction TB
                JIE["Collector Engine<br>(Stateless Go CLI)"] -->|2a. Output Payloads| H["📄 Evidence Payloads<br>(Raw JSON / CSV / Text)"]
                KMS["🔑 Key A: Evidence Signing<br>(Cloud KMS Asymmetric)"] -.->|Sign Manifest + Provenance| Sign["Signing Engine"]
                Sign -->|2b. Provenance| P["🛡️ Provenance Sidecars<br>(*.prov.json)"]
                Sign -->|2c. Manifest| M["📜 Cryptographic Manifest<br>(manifest.json)"]
                Sign -->|2d. Execution Trace| L["📝 Sanitized Logs<br>(run.log.gz)"]
            end

            subgraph Phase3 ["3. Immutable Attestation Ledger"]
                direction TB
                GCS[("🪣 Secure Object Storage<br>ledger://jula-ledger-{cloud_id}<br>(Versioned + Audit Logged)")]
                H -->|Upload| GCS
                P -->|Upload| GCS
                M -->|Upload| GCS
                L -->|Upload| GCS
            end

            subgraph Phase4 ["4. Continuous Assurance Layer (assessor/)"]
                direction TB
                EE["🔍 Assessor Engine<br>(Stateless Go CLI)"]

                subgraph GK ["Gatekeeper Verification"]
                    direction LR
                    SigCheck["✅ Manifest Verify<br>(Key A Public)"]
                    HashCheck["✅ Integrity Check<br>(Hash Comparison)"]
                    ProvCheck["🛡️ Provenance Verify<br>(Sidecar Check)"]
                    PolicyCheck["✅ Bundle Verify<br>(Key B Public)"]
                end

                OPA["⚙️ Embedded OPA Engine<br>(Dynamic Rego Execution)"]
                KeyC["🔑 Key C: Verdict Signing<br>(JULA_ASSESSOR_SIGNING_KEY)"]

                EE --> SigCheck
                SigCheck --> HashCheck
                HashCheck --> ProvCheck
                ProvCheck --> PolicyCheck
                PolicyCheck --> OPA

                Findings["🏆 Compliance Findings<br>(assessor_ledger.json + OSCAL AR)"]
                SignedVerdict["🛡️ Signed Verdict<br>(verdict.json)"]
            end
        end
    end

    %% Core Data Relationships
    JC -.->|Shared Schema + Crypto| JIE
    JC -.->|Shared Schema + Crypto| EE
    JC -.->|Shared Schema + Crypto| DB

    %% Governor injections (Crossing into Client Cloud)
    PR_Int -.->|Stream Integrations| JIE
    Meta -.->|Publish Scopes| EE
    PR_Norm -.->|Stream Adapters| OPA
    PR_Pol -.->|Stream Rego Policies| OPA
    BundleManifest -.->|Deploy Signed Bundle| PolicyCheck

    %% Execution flow (Inside Client Cloud)
    GCS -->|Pull Signed Ledger Run| SigCheck
    OPA -->|Audit Logs| Findings
    KeyC -.->|Sign Verdict| SignedVerdict
    Findings --> SignedVerdict
    
    %% Connection from external workloads into compliance environment
    APIs <-->|1. Extract Configuration| JIE

    %% Execution flow (Exiting Client Cloud via VPN/IAM)
    SignedVerdict -.->|Pull Verdicts| VerdictGate

    %% ══ Apply Styling Assignments ══
    class Cat,Req,PR_Int,PR_Norm,PR_Pol,Meta governor;
    class APIs,JIE,H,Sign,P,M,L collector;
    class EE,OPA assessor;
    class DB,Summary,Coverage,TrendMod,Maturity,FAIR,ROI,Export,MCP reporter;
    class GCS ledger;
    class JC core;

    %% Intermediate Policy Bundles (Rose Data)
    class BundleManifest dataBundle;

    %% Final Deliverables (Gold Artifacts)
    class Findings,SignedVerdict finalOutput;

    %% Keys
    class KMS keyA;
    class KeyB keyB;
    class KeyC keyC;

    %% Verification Bridges
    class SigCheck,ProvCheck verifyA;
    class PolicyCheck verifyB;
    class VerdictGate verifyC;
    class HashCheck verifyInteg;

    %% ══ Subgraph Canvas Fills (with visible borders) ══
    style Phase1 fill:#fff7ed,stroke:#fb923c,stroke-width:2px;
    style Phase2 fill:#f0f9ff,stroke:#93c5fd,stroke-width:2px;
    style Phase3 fill:#f8fafc,stroke:#94a3b8,stroke-width:2px;
    style Phase4 fill:#f0fdf4,stroke:#86efac,stroke-width:2px;
    style Phase5 fill:#faf5ff,stroke:#d8b4fe,stroke-width:2px;
    
    %% NEW: Client boundaries & background styling
    style ClientLocal fill:#fafaf9,stroke:#0f172a,stroke-width:3px;
    style ClientCloud fill:#fafaf9,stroke:#0f172a,stroke-width:3px;
    style TargetEnv fill:#fffbeb,stroke:#d97706,stroke-width:2px,stroke-dasharray: 5 5;
    style ComplianceEnv fill:#f8fafc,stroke:#334155,stroke-width:2px,stroke-dasharray: 10 5;

    linkStyle 24,25,26,27,28 stroke:#ea580c,stroke-width:2px;
    linkStyle 33 stroke:#2563eb,stroke-width:2px;
    linkStyle 34 stroke:#7c3aed,stroke-width:2px;
```

---

## Component Readiness

All modules build and pass unit tests. Reporter (🚧) has not been validated against live assessment output.

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

