# Configs: Declarative Extraction System

This directory contains the declarative configurations that drive the **Jula Evidence Collector**. In the "Collector-Only" architecture, these files define *what* raw infrastructure state to extract, but they contain no evaluation logic or compliance mapping.

## File Reference

| Directory | Purpose |
| :--- | :--- |
| `extractions/` | **Core Extraction Rules:** JSON files defining the queries used by the GCP, AWS, and SaaS engines to pull raw state. |
| `schemas/oscal/` | **Standardized Schemas:** OSCAL-formatted JSON definitions used by downstream tools (Jula EE) to map the raw ERL IDs to compliance frameworks (SCF, SOC 2, ISO 27001). |

## Extraction Configurations

### 1. Cloud Infrastructure
- **GCP (`gcp_cai.json`):** Defines the Resource Types and Content Types to extract via the Cloud Asset Inventory.
- **AWS (`aws_config.json`):** Defines the SQL-like Advanced Queries used to extract resource configurations from AWS Config.

### 2. SaaS & External APIs
- **SaaS (`saas_http.json`):** Defines the API endpoints, pagination logic, and authentication requirements for extracting state from third-party tools (e.g., GitHub, Aikido).

## Roadmap

The mapping of Evidence Request List (ERL) IDs to specific compliance frameworks (SOC 2, HIPAA, ISO 27001) is handled by the downstream **Jula EE** evaluator. This collector remains a high-performance, blind extraction engine that focuses purely on the cryptographic integrity and immutability of the evidence artifacts.
