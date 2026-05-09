# Remediation Templates

This directory contains parameterized Terraform modules that map directly to specific compliance violations flagged by the Jula Evidence Collector. When Jula reports a `FAIL` status for a given check, the corresponding template provides a production-ready, secure fix.

Each `.tf` file is self-contained and parameterized so that no hardcoded values like project IDs, IP ranges, or resource names are shipped. Your team provides those values via a `terraform.tfvars` file that stays in your own repository.

Files are prefixed by cloud provider (e.g., `gcp_`, `aws_`, `azure_`) and category to keep a flat, scannable layout.

## Template Index

| Template | Jula Finding | Framework Reference | Description |
| :--- | :--- | :--- | :--- |
| [aws_registry.tf](aws_registry.tf) | `aws.registry.lifecycle_policy == FAIL` | SOC 2 CC7.1, CC6.1 | Implements prefix-aware retention for ECR to protect builds. |
| [gcp_database.tf](gcp_database.tf) | `gcp.database.secure_config == FAIL` | SOC 2 CC6.1, A1.2 | Enforces SSL and point-in-time recovery for Cloud SQL. |
| [gcp_firewalls.tf](gcp_firewalls.tf) | `gcp.firewall.default_open == FAIL` | CIS GCP 3.6, 3.7 | Disables permissive default SSH and RDP firewall rules. |
| [gcp_iam.tf](gcp_iam.tf) | `gcp.iam.overprivileged_sa == FAIL` | SOC 2 CC6.1, CC6.3 | Binds scoped, least-privilege roles to CI/CD service accounts. |
| [gcp_kms.tf](gcp_kms.tf) | `gcp.kms.key_rotation == FAIL` | SOC 2 CC6.1 | Creates a CMEK with automatic 90-day rotation. |
| [gcp_logging.tf](gcp_logging.tf) | `gcp.audit_logging.enabled == FAIL` | SOC 2 CC2.1, CC7.2 | Enables Data Access audit logging globally for all GCP services. |
| [gcp_logging_alerts.tf](gcp_logging_alerts.tf) | `gcp.logging.cis_alerts == FAIL` | CIS GCP 2.1, 2.4, 2.5, 2.9 | Deploys log-based metrics and alert policies for administrative monitoring. |
| [gcp_registry.tf](gcp_registry.tf) | `gcp.registry.lifecycle_policy == FAIL` | SOC 2 CC6.1, CC7.1 | Implements the Tiered Union Strategy to protect releases and purge bloat. |
| [gcp_storage.tf](gcp_storage.tf) | `gcp.storage.encryption_enabled == FAIL` | SOC 2 C1.1 | Encrypts GCS buckets at rest using customer-managed KMS keys. |

## Example Workflow

```bash
# 1. Clone the template into your infra repo.
cp remediation/gcp_registry.tf my-infra/modules/

# 2. Create your private variables file.
cat > my-infra/modules/terraform.tfvars <<EOF
project_id = "my-company-prod-12345"
repository_name = "jula-evidence-collector"
EOF

# 3. Apply the fix.
cd my-infra/modules/
terraform init
terraform plan
terraform apply
```

## Multi-Cloud Roadmap

Current templates target **GCP** and **AWS**, representing the project's production-ready multi-cloud architecture. All templates follow the same prefix-based taxonomy (`provider_service.tf`) for consistent governance.
