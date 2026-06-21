package compliance.controls.jc_005

import rego.v1

# JC-005: Ensure automated backup and recovery is configured
# Applicable: GCP (Cloud SQL Backups)

evaluation := {
    "control_id": "JC-005",
    "compliant": result,
    "findings": findings,
    "evidence_used": ["EVID-GCP-SQL-INSTANCES"],
}

default result := false

result if {
    count(findings) == 0
}

# GCP: Check Cloud SQL automated backups
findings contains finding if {
    some evid, evidence in input.findings
    evidence.evidence_id == "EVID-GCP-SQL-INSTANCES"
    some instance in evidence.payload.items
    not instance.settings.backupConfiguration.enabled
    finding := {
        "severity": "MEDIUM",
        "resource": instance.name,
        "message": sprintf("Database instance '%s' does not have automated backups enabled", [instance.name]),
    }
}
