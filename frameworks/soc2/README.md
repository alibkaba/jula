# SOC 2 Trust Services Criteria: Control Coverage

This directory tracks the Jula Evidence Collector's coverage of SOC 2 Type II controls across all supported cloud environments.

## Status Legend

| Icon | Status | Description |
| :--- | :--- | :--- |
| ✅ | Mapped | Fully automated via native cloud API extraction. |
| 🟡 | BYOE-Required | Requires the client to drop evidence into a FileDrop bucket. |
| 🔵 | Partial | Partially automated; some manual supplementation may be needed. |
| ❌ | Out-of-Scope | Not targeted for automated collection. |

## Control Families

| Family | Document | Status |
| :--- | :--- | :--- |
| CC1: Control Environment | cc1_control_environment.md (BYOE) | 🟡 BYOE |
| CC2: Communication and Information | cc2_communication_and_information.md (BYOE) | 🔵 Partial |
| CC3: Risk Assessment | cc3_risk_assessment.md (BYOE) | 🟡 BYOE |
| CC4: Monitoring of Controls | cc4_monitoring_of_controls.md (BYOE) | 🟡 BYOE |
| CC5: Control Activities | cc5_control_activities.md (TBD) | ✅ Mapped |
| CC6: Logical and Physical Access | [cc6_logical_and_physical_access.md](cc6_logical_and_physical_access.md) | 🔵 Partial |
| CC7: System Operations | [cc7_system_operations.md](cc7_system_operations.md) | 🔵 Partial |
| CC8: Change Management | cc8_change_management.md (TBD) | ✅ Mapped |
| CC9: Risk Mitigation | cc9_risk_mitigation.md (BYOE) | 🟡 BYOE |
| Availability | availability.md (TBD) | ✅ Mapped |
| Confidentiality | confidentiality.md (TBD) | ✅ Mapped |

## Scope Exclusions

The following Trust Services Categories are **not** targeted by Jula and are explicitly out of scope:

* **Privacy**
* **Processing Integrity**
