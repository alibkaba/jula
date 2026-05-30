package compliance.controls.aikido_repos

default evaluation = {
    "control_id": "AIK-REPOS-1",
    "customer_control_id": "",
    "compliant": false,
    "drift_detected": false,
    "details": "Evaluation failed: no active repositories found or scan status is invalid",
    "service": "Aikido Security Repos"
}

# Extract raw_data from evidence
raw_data := input.findings["EVID-AIK-REPOS"][_].raw_data

# A repository is active if active == true
inactive_repos[repo] {
    repo := raw_data[_]
    repo.active != true
}

is_compliant {
    count(raw_data) > 0
    count(inactive_repos) == 0
}

evaluation = {
    "control_id": "AIK-REPOS-1",
    "customer_control_id": "",
    "compliant": is_compliant,
    "drift_detected": false,
    "details": details,
    "service": "Aikido Security Repos"
}

details = sprintf("All monitored repositories are active and scanned (%d total).", [count(raw_data)]) {
    is_compliant
} else = sprintf("Inactive repositories found: %d of %d", [count(inactive_repos), count(raw_data)])
