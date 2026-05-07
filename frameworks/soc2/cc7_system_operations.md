# CC7: System Operations

**Description:** The entity detects and monitors system anomalies, manages vulnerabilities, and recovers from security incidents in a timely manner.

## Control Coverage Status

| Criterion | Jula Internal ID | Status | Extraction Method | Target Cloud/System | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CC7.1** | `byoe.vulnerability_scan` | 🟡 BYOE-Required | FileDrop (Parsed) | Any | Requires JSON schema upload of scan results |
| **CC7.2** | `gcp.audit_logging.enabled` | ✅ Mapped | Native API | GCP | Cloud Audit Logging enablement |
| **CC7.2** | `aws.guardduty.enabled` | ✅ Mapped | Native API | AWS | GuardDuty threat detection enablement |
| **CC7.3** | `byoe.incident_response_plan` | 🟡 BYOE-Required | FileDrop (Hashed) | Any | Requires PDF drop of IR plan to bucket |
| **CC7.4** | `byoe.incident_response_plan` | 🟡 BYOE-Required | FileDrop (Hashed) | Any | Shares evidence with CC7.3 |

## Implementation Details

### CC7.1 (Vulnerability Management)

* **Tested Environments:** AWS S3 Bucket (FileDrop)
* **Schema Requirement:** `configs/schemas/byoe_vulnerability_scan.json`
* **Data Requirement:** Client must export vulnerability scan results as JSON conforming to the BYOE schema. Jula parses the `findings_summary` to evaluate severity counts.

### CC7.2 (Anomaly Detection - GCP)

* **Tested Environments:** GCP (global)
* **Jula Mapping Rule:** `soc2-cc7.2-audit-logging`
* **What It Checks:** Validates that Cloud Audit Logging is enabled for the project.

### CC7.2 (Anomaly Detection - AWS)

* **Tested Environments:** AWS (us-east-1)
* **Jula Mapping Rule:** `soc2-cc7.2-guardduty`
* **What It Checks:** Validates that GuardDuty is enabled for the AWS account and region.

### CC7.3 / CC7.4 (Incident Response)

* **Tested Environments:** AWS S3 Bucket (FileDrop)
* **Data Requirement:** Client drops the current Incident Response Plan as a `.pdf` file into the `/policies/` prefix of the FileDrop bucket. Jula generates a SHA-256 hash and timestamp as proof of existence and maintenance.
