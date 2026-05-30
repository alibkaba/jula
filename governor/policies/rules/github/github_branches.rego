package compliance.controls.github_branches

default evaluation = {
    "control_id": "GH-BRANCHES-1",
    "customer_control_id": "",
    "compliant": false,
    "drift_detected": false,
    "details": "Evaluation failed: main branch is not protected",
    "service": "GitHub Branches"
}

# Extract raw_data from evidence
raw_data := input.findings["EVID-GH-BRANCHES"][_].raw_data

main_is_protected {
    branch := raw_data[_]
    branch.name == "main"
    branch.protected == true
}

evaluation = {
    "control_id": "GH-BRANCHES-1",
    "customer_control_id": "",
    "compliant": main_is_protected,
    "drift_detected": false,
    "details": details,
    "service": "GitHub Branches"
}

details = "Main branch is correctly protected." {
    main_is_protected
} else = "Main branch is not protected."
