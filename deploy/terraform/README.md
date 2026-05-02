# Jula Evidence Collector – Terraform Deployment

This directory contains the Infrastructure as Code (IaC) for deploying the Jula Evidence Collector to Google Cloud Platform.

## Quick Start

```bash
# 1. Install Terraform (https://developer.hashicorp.com/terraform/install)

# 2. Create your config file (this is the ONLY file you edit)
cp terraform.tfvars.example terraform.tfvars

# 3. Fill in your GCP project ID and image URI in terraform.tfvars

# 4. Initialize and deploy
terraform init
terraform plan     # Preview changes
terraform apply    # Deploy
```

## File Reference

| File | Purpose | Edit? |
|:---|:---|:---|
| `terraform.tfvars.example` | Template with placeholder values | No, copy it |
| `terraform.tfvars` | **Your actual config (created from the template)** | **Yes, this is the only file you edit** |
| `main.tf` | Resource definitions (Cloud Run, GCS, IAM, etc.) | No |
| `variables.tf` | Variable declarations and defaults | No |
| `outputs.tf` | Post-deploy outputs (service URL, bucket name) | No |
| `.terraform.lock.hcl` | Provider version lock | No |

## What Gets Created

Running `terraform apply` provisions the following GCP resources:

- **Service Account** with least-privilege IAM roles
- **GCS Bucket** for signed evidence artifacts (versioning enabled)
- **Secret Manager** secret for the HMAC signing key
- **Cloud Run** service running the Jula container
- **Cloud Scheduler** job for automated weekly collection

## Important

The `terraform.tfvars` file is gitignored and will never be committed. It contains your environment-specific values (project ID, region, image URI).
