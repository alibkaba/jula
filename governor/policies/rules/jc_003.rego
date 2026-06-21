package compliance.controls.jc_003

import rego.v1

# JC-003: Ensure uniform policy-based access control is enforced
# Applicable: GCP (Uniform Bucket-Level Access)

evaluation := {
    "control_id": "JC-003",
    "compliant": result,
    "findings": findings,
    "evidence_used": ["EVID-GCP-STORAGE-BUCKETS"],
}

default result := false

result if {
    count(findings) == 0
}

# GCP: Check uniform bucket-level access
findings contains finding if {
    some evid, evidence in input.findings
    evidence.evidence_id == "EVID-GCP-STORAGE-BUCKETS"
    some bucket in evidence.payload.items
    not bucket.iamConfiguration.uniformBucketLevelAccess.enabled
    finding := {
        "severity": "MEDIUM",
        "resource": bucket.name,
        "message": sprintf("Storage resource '%s' uses legacy per-object ACLs instead of uniform policy-based access", [bucket.name]),
    }
}
