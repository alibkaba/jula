package compliance.controls.aikido_soc2

default evaluation = {
    "control_id": "AIK-SOC2-1",
    "customer_control_id": "",
    "compliant": false,
    "drift_detected": false,
    "details": "Evaluation failed: SOC2 compliance overview unavailable",
    "service": "Aikido Security SOC2"
}

# Extract raw_data from evidence
raw_data := input.findings["EVID-AIK-SOC2"][_].raw_data

# Verify compliance score is at least 90%
is_compliant {
    complying := raw_data.total_complying_rule_count
    total := raw_data.total_rule_count
    total > 0
    (complying * 100) / total >= 90
}

evaluation = {
    "control_id": "AIK-SOC2-1",
    "customer_control_id": "",
    "compliant": is_compliant,
    "drift_detected": false,
    "details": details,
    "service": "Aikido Security SOC2"
}

details = sprintf("SOC2 compliance is at %d%% (%d of %d rules complying).", [
    (raw_data.total_complying_rule_count * 100) / raw_data.total_rule_count,
    raw_data.total_complying_rule_count,
    raw_data.total_rule_count
]) {
    is_compliant
} else = sprintf("SOC2 compliance is below 90%%: at %d%% (%d of %d rules complying).", [
    (raw_data.total_complying_rule_count * 100) / raw_data.total_rule_count,
    raw_data.total_complying_rule_count,
    raw_data.total_rule_count
])
