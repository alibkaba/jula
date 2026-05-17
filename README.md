# Jula Controls: Compliance Policies

This repository houses the version-controlled compliance policies and controls mapping written in Open Policy Agent (OPA) Rego language. It serves as the single source of truth for all security compliance evaluation rules executed by the downstream **[Jula Evidence Evaluator](https://github.com/alibkaba/jula-evidence-evaluator)** Assurance Engine. Raw security evidence is programmatically extracted from cloud and SaaS environments using the upstream **[Jula Evidence Collector](https://github.com/alibkaba/jula-evidence-collector)**.

## Repository Structure

```
/policies
  /gcp
    gcp_db_encryption.rego        # E-BCM-16: Encrypted Database Instances
    gcp_db_encryption_test.rego   # OPA Unit tests for database encryption
    gcp_storage_security.rego     # E-DCH-10: GCS Storage Security checks
    gcp_storage_security_test.rego # OPA Unit tests for GCS storage security
```

## Running Policy Tests Locally

You can test all policies locally using the standard OPA CLI tool.

### Using Local OPA CLI
```bash
opa test ./policies/... -v
```

### Using Docker Container
If you do not have the OPA CLI installed locally, you can run tests in an isolated Docker container:
```bash
docker run --rm -v "$(pwd):/policies" openpolicyagent/opa:latest test /policies/policies -v
```
