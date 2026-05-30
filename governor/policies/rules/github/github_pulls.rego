package compliance.controls.github_pulls

default evaluation = {
    "control_id": "GH-PULLS-1",
    "customer_control_id": "",
    "compliant": false,
    "drift_detected": false,
    "details": "Evaluation failed: open pull requests with WIP titles found",
    "service": "GitHub Pulls"
}

# Extract raw_data from evidence
raw_data := input.findings["EVID-GH-PULLS"][_].raw_data

# Find any open pull request that has 'WIP' or 'wip' in the title
wip_prs[pr] {
    pr := raw_data[_]
    pr.state == "open"
    contains(lower(pr.title), "wip")
}

is_compliant {
    count(wip_prs) == 0
}

evaluation = {
    "control_id": "GH-PULLS-1",
    "customer_control_id": "",
    "compliant": is_compliant,
    "drift_detected": false,
    "details": details,
    "service": "GitHub Pulls"
}

details = "All open pull requests are compliant with naming guidelines." {
    is_compliant
} else = sprintf("Non-compliant open PRs with WIP status found: %d", [count(wip_prs)])
