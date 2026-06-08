# Claude GRC Engineering Evaluation Report

This report documents the architectural patterns, data contracts, and framework mapping mechanisms of the `claude-grc-engineering` toolkit. It analyzes these components relative to the design of the Jula evidence collection and evaluation engine.

---

## 1. Executive Summary

We have evaluated the `claude-grc-engineering` repository (v0.0.4) to understand its approach to Governance, Risk, and Compliance (GRC) automation. The tool functions as a marketplace of Claude Code plugins, orchestrating compliance assessment, evidence checks, and gap analysis. 

While Jula is designed as a lightweight, Go-based local collection and Open Policy Agent (OPA) validation engine, `claude-grc-engineering` is built as a multi-layered Node.js plugin framework tailored for conversational agent execution.

---

## 2. Architecture and Data Flow

The `claude-grc-engineering` toolkit is structured as a three-tier pipeline:

* The **plugin marketplace layer** exposes framework-specific and role-based commands directly to the user interface.

* The **engineering hub** (namespace `/grc-engineer`) handles core compliance logic, executing static analysis, continuous monitoring, and gap assessments.

* The **connector layer** runs external scanner binaries (such as Prowler, AWS Inspector, or Wiz) and normalizes their outputs into a standard format.

---

## 3. Comparative Analysis: Jula vs. Claude GRC

There are key conceptual differences in how both systems approach compliance data and evaluation:

| Dimension | Jula Evidence Engine | Claude GRC Engineering |
|---|---|---|
| **Primary Language** | Go | JavaScript / Node.js |
| **Execution Environment** | CLI (Dockerized runner, local binaries) | Interactive conversational plugins (Claude Code, MCP) |
| **"Finding" Definition** | Raw, unevaluated infrastructure state (opaque payload) | Post-evaluation status (pass/fail check result on a resource) |
| **Evaluation Engine** | Open Policy Agent (OPA) / Rego policies | External tools + Javascript logic parsing JSON findings |
| **Framework Mapping** | Static OSCAL-generated maps | Live Secure Controls Framework (SCF) API mapping |
| **Remediation** | Audit attestation only (no remediation code generation) | Automated generation of Terraform and script fixes |

### The Finding Concept Divergence

In Jula, a **Finding** is a pure container for raw infrastructure state data, represented as raw bytes in the `RawData` field. It contains no compliance verdict. Downstream evaluation engines (OPA/Rego) query this raw data to determine compliance.

In contrast, a **Finding** in `claude-grc-engineering` is an evaluation output. The resource check has already occurred, and the Finding documents whether the resource passed or failed a specific control requirement.

---

## 4. Control Mapping and Framework Coverage

The `claude-grc-engineering` toolkit uses the **Secure Controls Framework (SCF)** as its central control vocabulary, resolving framework-specific rules via a live API.

* The **canonical control set** maps 1,468 SCF controls across 33 families to 249 compliance frameworks.

* The **shipped plugins** provide custom reference guides and commands for 15 primary frameworks, including SOC 2, NIST 800-53, DORA, and ISO 27001.

* The **evaluation process** maps raw findings to SCF IDs, then projects those IDs onto the target frameworks to determine multi-framework compliance.

---

## 5. Architectural Takeaways for Jula

Although Jula will not integrate with this toolkit, several design patterns are worth noting for future Jula development:

* We can **adopt the status-severity matrix separation** to decouple a control's operational status (pass/fail) from its security impact (critical/high/medium/low).

* We can **utilize structured JSON contracts** for connector tool evaluations, ensuring that any custom scanners we add emit reproducible compliance records.

* We can **maintain clean data caches** (matching their `.cache/claude-grc/` approach) to allow Jula's evaluator to run checks offline using cached evidence.
