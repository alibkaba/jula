package compliance.controls.aikido_issues

default evaluation = {
    "control_id": "AIK-ISSUES-1",
    "customer_control_id": "",
    "compliant": false,
    "drift_detected": false,
    "details": "Evaluation failed: open critical issues found",
    "service": "Aikido Security Issues"
}

# Extract raw_data from evidence
raw_data := input.findings["EVID-AIK-ISSUES"][_].raw_data

open_critical_issues[issue] {
    issue := raw_data[_]
    issue.status == "open"
    issue.severity == "critical"
}

is_compliant {
    count(open_critical_issues) == 0
}

evaluation = {
    "control_id": "AIK-ISSUES-1",
    "customer_control_id": "",
    "compliant": is_compliant,
    "drift_detected": false,
    "details": details,
    "service": "Aikido Security Issues"
}

details = "No open critical issues found in Aikido." {
    is_compliant
} else = sprintf("Open critical issues found: %d", [count(open_critical_issues)])
