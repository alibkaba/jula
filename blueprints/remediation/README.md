# Remediation Blueprints

This directory contains parameterized Terraform modules that map directly to specific compliance violations flagged by the Jula Evidence Collector. When Jula reports a `FAIL` status for a given check, the corresponding blueprint in this directory provides a production-ready, secure fix.

## How It Works

Each `.tf` file is a self-contained, parameterized module. We never ship hardcoded values like project IDs, IP ranges, or resource names. Instead, every environment-specific detail is abstracted into a Terraform **variable**.

Your team provides those values via a `terraform.tfvars` file that stays in your own repository and is never shared with us.

### Example Workflow

```bash
# 1. Clone the blueprint into your infra repo.
cp blueprints/remediation/audit_logging.tf my-infra/modules/

# 2. Create your private variables file.
cat > my-infra/modules/terraform.tfvars <<EOF
project_id = "my-company-prod-12345"
EOF

# 3. Apply the fix.
cd my-infra/modules/
terraform init
terraform plan
terraform apply
```

## Blueprint Index

| Blueprint | Jula Finding | SOC 2 Criteria | Description |
| :--- | :--- | :--- | :--- |
| [audit_logging.tf](audit_logging.tf) | `gcp.audit_logging.enabled == FAIL` | CC2.1, CC7.2 | Enables Data Access audit logging globally for all GCP services. |
| [cloud_sql.tf](cloud_sql.tf) | `gcp.sql.secure_config == FAIL` | CC6.1, A1.2 | Enforces Private IP and automated daily backups for Cloud SQL. |
| [kms_rotation.tf](kms_rotation.tf) | `gcp.kms.key_rotation == FAIL` | CC6.1 | Creates a CMEK with automatic 90-day rotation. |
| [storage_encryption.tf](storage_encryption.tf) | `gcp.storage.encryption_enabled == FAIL` | C1.1 | Encrypts a GCS bucket at rest using a customer-managed KMS key. |

## Security Note

These blueprints are designed for Google Cloud Platform (GCP), which is the environment where Jula is fully configured, tested, and deployed in production. The parameterized variable pattern is cloud-agnostic, so equivalent AWS and Azure blueprints can follow the same structure as those providers mature.
