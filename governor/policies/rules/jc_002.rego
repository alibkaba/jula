package compliance.controls.jc_002

import rego.v1

# JC-002: Ensure data versioning and recovery is enabled
# Applicable: AWS (S3 Versioning), GCP (Storage lifecycle)

evaluation := {
    "control_id": "JC-002",
    "compliant": result,
    "findings": findings,
    "evidence_used": ["EVID-AWS-S3-VERSIONING"],
}

default result := false

result if {
    count(findings) == 0
}

# AWS: Check S3 versioning is enabled
findings contains finding if {
    some evid, evidence in input.findings
    evidence.evidence_id == "EVID-AWS-S3-VERSIONING"
    status := object.get(evidence.payload, "Status", "Disabled")
    status != "Enabled"
    finding := {
        "severity": "MEDIUM",
        "resource": evidence.payload.BucketName,
        "message": sprintf("Storage bucket '%s' does not have versioning enabled (status: '%s')", [evidence.payload.BucketName, status]),
    }
}
