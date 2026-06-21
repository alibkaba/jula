package compliance.controls.jc_007

import rego.v1

# JC-007: Ensure workloads use least-privilege identities
# Applicable: GCP (Compute default service account)

evaluation := {
    "control_id": "JC-007",
    "compliant": result,
    "findings": findings,
    "evidence_used": ["EVID-GCP-COMPUTE-INSTANCES"],
}

default result := false

result if {
    count(findings) == 0
}

# GCP: Check for default Compute Engine service account
findings contains finding if {
    some evid, evidence in input.findings
    evidence.evidence_id == "EVID-GCP-COMPUTE-INSTANCES"
    some zone_data in evidence.payload.items
    some instance in zone_data.instances
    some sa in instance.serviceAccounts
    contains(sa.email, "-compute@developer.gserviceaccount.com")
    finding := {
        "severity": "HIGH",
        "resource": instance.name,
        "message": sprintf("Workload '%s' uses default platform identity '%s'", [instance.name, sa.email]),
    }
}
