package compliance.controls.jc_004

import rego.v1

# JC-004: Ensure data in transit is encrypted
# Applicable: GCP (Cloud SQL SSL)

evaluation := {
    "control_id": "JC-004",
    "compliant": result,
    "findings": findings,
    "evidence_used": ["EVID-GCP-SQL-INSTANCES"],
}

default result := false

result if {
    count(findings) == 0
}

# GCP: Check Cloud SQL SSL enforcement
findings contains finding if {
    some evid, evidence in input.findings
    evidence.evidence_id == "EVID-GCP-SQL-INSTANCES"
    some instance in evidence.payload.items
    ssl_mode := object.get(instance.settings.ipConfiguration, "sslMode", "ALLOW_UNENCRYPTED_AND_ENCRYPTED")
    ssl_mode != "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
    ssl_mode != "ENCRYPTED_ONLY"
    finding := {
        "severity": "HIGH",
        "resource": instance.name,
        "message": sprintf("Database instance '%s' does not enforce encrypted connections (mode: '%s')", [instance.name, ssl_mode]),
    }
}
