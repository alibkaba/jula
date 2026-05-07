# CC6: Logical and Physical Access Controls

**Description:** The entity restricts logical and physical access to information assets through access controls, network segmentation, and encryption.

## Control Coverage Status

| Criterion | Jula Internal ID | Status | Extraction Method | Target Cloud/System | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CC6.1** | `gcp.iam.service_account_key_rotation` | ✅ Mapped | Native API | GCP | Verifies SA key rotation policy |
| **CC6.1** | `gcp.sql.secure_config` | ✅ Mapped | Native API | GCP | Cloud SQL private IP enforcement |
| **CC6.1** | `gcp.kms.key_rotation` | ✅ Mapped | Native API | GCP | KMS automatic key rotation |
| **CC6.2** | `byoe.user_access_review` | 🟡 BYOE-Required | FileDrop (Parsed) | Any | Requires JSON upload of access review results |
| **CC6.3** | `byoe.user_access_review` | 🟡 BYOE-Required | FileDrop (Parsed) | Any | Shares evidence with CC6.2 |
| **CC6.6** | `gcp.compute.firewall_ingress` | ✅ Mapped | Native API | GCP | Evaluates Compute Engine firewall ingress rules |
| **CC6.7** | `byoe.network_security` | 🟡 BYOE-Required | FileDrop (Hashed) | Any | On-prem firewall state exported to cloud bucket |

## Implementation Details

### CC6.1 (Service Account Key Rotation)

* **Tested Environments:** GCP (global)
* **Jula Mapping Rule:** `soc2-cc6.1-sa-key-rotation`
* **What It Checks:** Validates that service account keys have been rotated within the configured policy window.

### CC6.1 (Cloud SQL Private IP)

* **Tested Environments:** GCP (us-central1)
* **Jula Mapping Rule:** `soc2-cc6.1-sql-private`
* **What It Checks:** Confirms Cloud SQL instances are configured with private IP only (no public access).

### CC6.1 (KMS Key Rotation)

* **Tested Environments:** GCP (global)
* **Jula Mapping Rule:** `soc2-cc6.1-kms-rotation`
* **What It Checks:** Validates that KMS keys have automatic rotation enabled.

### CC6.2 / CC6.3 (User Access Reviews)

* **Tested Environments:** AWS S3 Bucket (FileDrop)
* **Schema Requirement:** Custom JSON schema for access review exports
* **Data Requirement:** Client must export access review results as JSON to the designated FileDrop bucket.

### CC6.6 (Firewall Ingress Rules)

* **Tested Environments:** GCP (global)
* **Jula Mapping Rule:** `soc2-cc6.6-compute-firewalls`
* **What It Checks:** Evaluates all Compute Engine firewall rules for overly permissive ingress (e.g., 0.0.0.0/0 on sensitive ports).

### CC6.7 (Network Security - Hybrid)

* **Tested Environments:** AWS S3 Bucket (FileDrop)
* **Data Requirement:** Client runs a local script to dump on-premises firewall configuration and uploads the output to the designated FileDrop bucket. Jula hashes the file as proof of collection.
