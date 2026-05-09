# Deploy: Internal Infrastructure (Decoupled)

> **This directory is not for clients.** The Terraform in this folder provisions the isolated environments where the Jula Evidence Collector runs. 

## Architecture

This infrastructure is decoupled into cloud-specific modules to ensure failure domain isolation:

- [`gcp/`](gcp/): Provisions Cloud Run, GCS, Secret Manager, and Scheduler.
- [`aws/`](aws/): Provisions ECR Registry and IAM OIDC Role.

## Quick Start

The deployment uses a dockerized wrapper to ensure consistency.

### 1. Initialize Providers

```bash
./scripts/terraform.sh init gcp
./scripts/terraform.sh init aws
```

### 2. Configure Variables

Create `terraform.tfvars` in the respective subdirectories.

### 3. Deploy

```bash
# Deploy GCP stack
./scripts/terraform.sh apply gcp

# Deploy AWS stack
./scripts/terraform.sh apply aws
```

## Why Decouple?

By separating the state files:
1. **Isolation**: A transient error or API outage in GCP will not block management of AWS resources.
2. **Parallelism**: CI/CD pipelines can execute both deployments concurrently.
3. **Least Privilege**: Deployment runners can be scoped to specific cloud credentials per job.

## Security

Ensure `terraform.tfvars` and `.tfstate` files remain local and are never committed. OIDC is used for GitHub Actions to avoid long-lived IAM keys.
