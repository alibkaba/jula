package compliance.controls.jc_008

import rego.v1

# JC-008: Ensure privileged credentials are not persistent
# Applicable: AWS (Root account access keys)

evaluation := {
    "control_id": "JC-008",
    "compliant": result,
    "findings": findings,
    "evidence_used": ["EVID-AWS-IAM-ACCESS-KEYS"],
}

default result := false

result if {
    count(findings) == 0
}

# AWS: Check for active root account access keys
findings contains finding if {
    some evid, evidence in input.findings
    evidence.evidence_id == "EVID-AWS-IAM-ACCESS-KEYS"
    some key in evidence.payload.AccessKeyMetadata
    key.UserName == "root"
    key.Status == "Active"
    finding := {
        "severity": "CRITICAL",
        "resource": "root",
        "message": sprintf("Privileged root identity has an active persistent credential (key: '%s')", [key.AccessKeyId]),
    }
}
