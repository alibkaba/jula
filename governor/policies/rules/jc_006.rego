package compliance.controls.jc_006

import rego.v1

# JC-006: Ensure services are not exposed to the public internet
# Applicable: AWS (RDS public accessibility)

evaluation := {
    "control_id": "JC-006",
    "compliant": result,
    "findings": findings,
    "evidence_used": ["EVID-AWS-RDS-INSTANCES"],
}

default result := false

result if {
    count(findings) == 0
}

# AWS: Check RDS public accessibility
findings contains finding if {
    some evid, evidence in input.findings
    evidence.evidence_id == "EVID-AWS-RDS-INSTANCES"
    some db_instance in evidence.payload.DBInstances
    db_instance.PubliclyAccessible == true
    finding := {
        "severity": "CRITICAL",
        "resource": db_instance.DBInstanceIdentifier,
        "message": sprintf("Database instance '%s' is publicly accessible from the internet", [db_instance.DBInstanceIdentifier]),
    }
}
