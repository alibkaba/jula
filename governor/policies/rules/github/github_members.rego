package compliance.controls.github_members

default evaluation = {
    "control_id": "GH-MEMBERS-1",
    "customer_control_id": "",
    "compliant": false,
    "drift_detected": false,
    "details": "Evaluation failed: members list is empty",
    "service": "GitHub Members"
}

# Extract raw_data from evidence
raw_data := input.findings["EVID-GH-MEMBERS"][_].raw_data

# The members policy is compliant if the endpoint returns null (no organization context/personal scope),
# or if it returns a non-empty list of organization members.
is_compliant {
    raw_data == null
}

is_compliant {
    raw_data != null
    count(raw_data) > 0
}

evaluation = {
    "control_id": "GH-MEMBERS-1",
    "customer_control_id": "",
    "compliant": is_compliant,
    "drift_detected": false,
    "details": details,
    "service": "GitHub Members"
}

details = "Members policy is compliant (personal account scope or non-empty organization members)." {
    is_compliant
} else = "No organization members found."
