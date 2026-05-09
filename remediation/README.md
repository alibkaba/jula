# Remediation Templates

This directory contains parameterized Terraform modules that map directly to specific compliance violations flagged by the Jula Evidence Collector. When Jula reports a `FAIL` status for a given check, the corresponding template provides a production-ready, secure fix.

Each `.tf` file is self-contained and parameterized so that no hardcoded values like project IDs, IP ranges, or resource names are shipped. Your team provides those values via a `terraform.tfvars` file that stays in your own repository.

Files are prefixed by cloud provider (e.g., `gcp_`, `aws_`, `azure_`) to keep a flat, scannable layout.

## Template Index

| Template | Jula Finding | Framework Reference | Description |
| :--- | :--- | :--- | :--- |
| [gcp_audit_logging.tf](gcp_audit_logging.tf) | `gcp.audit_logging.enabled == FAIL` | SOC 2 CC2.1, CC7.2 | Enables Data Access audit logging globally for all GCP services. |
| [gcp_cis_log_alerts.tf](gcp_cis_log_alerts.tf) | `gcp.logging.cis_alerts == FAIL` | CIS GCP 2.1, 2.4, 2.5, 2.9 | Deploys log-based metrics and alert policies for administrative monitoring. |
| [gcp_cloud_sql.tf](gcp_cloud_sql.tf) | `gcp.sql.secure_config == FAIL` | SOC 2 CC6.1, A1.2 | Enforces Private IP and automated daily backups for Cloud SQL. |
| [gcp_firewall_hardening.tf](gcp_firewall_hardening.tf) | `gcp.firewall.default_open == FAIL` | CIS GCP 3.6, 3.7 | Disables permissive default SSH and RDP firewall rules. |
| [gcp_kms_rotation.tf](gcp_kms_rotation.tf) | `gcp.kms.key_rotation == FAIL` | SOC 2 CC6.1 | Creates a CMEK with automatic 90-day rotation. |
| [gcp_least_privilege_iam.tf](gcp_least_privilege_iam.tf) | `gcp.iam.overprivileged_sa == FAIL` | SOC 2 CC6.1, CC6.3 | Binds scoped, least-privilege roles to CI/CD service accounts. |
| [gcp_storage_encryption.tf](gcp_storage_encryption.tf) | `gcp.storage.encryption_enabled == FAIL` | SOC 2 C1.1 | Encrypts a GCS bucket at rest using a customer-managed KMS key. |


## The Culture Shift: Why This Matters

Technical fixes are temporary; culture is permanent. Each of these templates is designed to enforce a specific behavioral shift within your engineering team.

| Template | The Technical Fix | The Culture Shift (The "Why") |
| :--- | :--- | :--- |
| **Audit Logging** | API enablement | **Absolute Accountability**: Establishing a culture where every administrative action is a "recorded event," reducing the urge for "heroic" manual fixes in production. |
| **Least Privilege** | IAM binding | **Need-to-Know by Default**: Moving away from "Full Admin" convenience toward a culture of scoped, temporary, and justified access. |
| **Firewall Hardening** | Port restriction | **Zero-Trust Networking**: Reinforcing the mindset that the internal network is not a "safe zone" and that all entry points must be explicit and defended. |
| **KMS Rotation** | Key management | **Cryptographic Lifecycle**: Educating teams that security is a moving target; static secrets are liabilities, and rotation is a standard operational rhythm. |

## Example Workflow

```bash
# 1. Clone the template into your infra repo.
cp remediation/gcp_audit_logging.tf my-infra/modules/

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

## Multi-Cloud Roadmap

All current templates target Google Cloud Platform, which is the environment where Jula is fully configured, tested, and deployed in production. The parameterized variable pattern is cloud-agnostic, so equivalent `aws_` and `azure_` prefixed templates can follow the same structure as those providers mature.
