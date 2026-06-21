package compliance.controls.jc_009

import rego.v1

# JC-009: Ensure credential rotation meets policy requirements
# Applicable: GCP (Service account key age)

evaluation := {
    "control_id": "JC-009",
    "compliant": result,
    "findings": findings,
    "evidence_used": ["EVID-GCP-IAM-SA-KEYS"],
}

default result := false

result if {
    count(findings) == 0
}

# GCP: Check service account key age (90-day max)
findings contains finding if {
    some evid, evidence in input.findings
    evidence.evidence_id == "EVID-GCP-IAM-SA-KEYS"
    some key in evidence.payload.keys
    key.keyType == "USER_MANAGED"
    key_age_ns := time.now_ns() - time.parse_rfc3339_ns(key.validAfterTime)
    key_age_days := key_age_ns / (24 * 60 * 60 * 1000000000)
    key_age_days > 90
    finding := {
        "severity": "MEDIUM",
        "resource": key.name,
        "message": sprintf("Service credential '%s' is %d days old, exceeding the 90-day rotation policy", [key.name, key_age_days]),
    }
}
