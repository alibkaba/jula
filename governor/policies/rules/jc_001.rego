package compliance.controls.jc_001

import rego.v1

# JC-001: Ensure data resources are not publicly exposed
# Applicable: GCP (Storage IAM), AWS (S3 PublicAccessBlock)

evaluation := {
    "control_id": "JC-001",
    "compliant": result,
    "findings": findings,
    "evidence_used": ["EVID-GCP-STORAGE-IAM", "EVID-AWS-S3-PUBLIC-ACCESS"],
}

default result := false

result if {
    count(findings) == 0
}

# GCP: Check for allUsers or allAuthenticatedUsers in storage IAM bindings
findings contains finding if {
    some evid, evidence in input.findings
    evidence.evidence_id == "EVID-GCP-STORAGE-IAM"
    some binding in evidence.payload.bindings
    some member in binding.members
    member in {"allUsers", "allAuthenticatedUsers"}
    finding := {
        "severity": "HIGH",
        "resource": evidence.payload.resourceId,
        "message": sprintf("Storage IAM grants public access via '%s' in role '%s'", [member, binding.role]),
    }
}

# AWS: Check S3 PublicAccessBlock is fully enabled
findings contains finding if {
    some evid, evidence in input.findings
    evidence.evidence_id == "EVID-AWS-S3-PUBLIC-ACCESS"
    config := evidence.payload.PublicAccessBlockConfiguration
    not config.BlockPublicAcls
    finding := {
        "severity": "HIGH",
        "resource": evidence.payload.BucketName,
        "message": sprintf("Storage bucket '%s' does not block public ACLs", [evidence.payload.BucketName]),
    }
}

findings contains finding if {
    some evid, evidence in input.findings
    evidence.evidence_id == "EVID-AWS-S3-PUBLIC-ACCESS"
    config := evidence.payload.PublicAccessBlockConfiguration
    not config.BlockPublicPolicy
    finding := {
        "severity": "HIGH",
        "resource": evidence.payload.BucketName,
        "message": sprintf("Storage bucket '%s' does not block public policies", [evidence.payload.BucketName]),
    }
}

findings contains finding if {
    some evid, evidence in input.findings
    evidence.evidence_id == "EVID-AWS-S3-PUBLIC-ACCESS"
    config := evidence.payload.PublicAccessBlockConfiguration
    not config.RestrictPublicBuckets
    finding := {
        "severity": "HIGH",
        "resource": evidence.payload.BucketName,
        "message": sprintf("Storage bucket '%s' does not restrict public access", [evidence.payload.BucketName]),
    }
}
