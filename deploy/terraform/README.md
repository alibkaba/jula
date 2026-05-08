# Deploy: Internal Infrastructure

> **This directory is not for clients.** The Terraform in this folder provisions the isolated GCP environment where the Jula Evidence Collector itself runs. It is internal operational infrastructure, not a client deliverable.

If you are looking for remediation templates to fix compliance violations flagged by Jula, see [`remediation/`](../../remediation/README.md).

## What This Deploys

Running `terraform apply` from this directory provisions the following resources into our controlled GCP project:

- **Service Account** with least-privilege IAM roles scoped to read-only infrastructure access.
- **GCS Bucket** for signed evidence artifacts (versioning enabled, CMEK encryption).
- **Secret Manager** secret for the HMAC signing key.
- **Cloud Run** service running the Jula container image (built from the root `Dockerfile`).
- **Cloud Scheduler** job for automated weekly evidence collection.

## Prerequisites

- Terraform >= 1.5
- Authenticated `gcloud` CLI with project-level `roles/editor` (or equivalent granular roles)
- A pre-built container image pushed to Artifact Registry

## Quick Start

```bash
# 1. Copy the example variables file.
cp terraform.tfvars.example terraform.tfvars

# 2. Populate terraform.tfvars with your project ID, region, and image URI.
#    This is the ONLY file you edit.

# 3. Initialize and deploy.
terraform init
terraform plan
terraform apply
```

## File Reference

| File | Purpose | Edit? |
| :--- | :--- | :--- |
| `terraform.tfvars.example` | Template with placeholder values | No, copy it to create your config |
| `main.tf` | Resource definitions (Cloud Run, GCS, IAM, Scheduler) | No |
| `variables.tf` | Variable declarations and defaults | No |
| `outputs.tf` | Post-deploy outputs (service URL, bucket name) | No |
| `.terraform.lock.hcl` | Provider version lock | No |

## Security

The `terraform.tfvars` file is `.gitignore`'d and must never be committed. It contains environment-specific values including project IDs and image URIs. The `terraform.tfstate` files contain sensitive infrastructure state and are also excluded from version control.
