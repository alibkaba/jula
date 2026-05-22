package compliance.scf.vpm_05_test

import rego.v1
import data.compliance.scf.vpm_05

# Helper to build mock input with a single ERL source
mock_input(erl_id, issues) = {
	"findings": {
		erl_id: {
			"aikido_src": {
				"raw_data": issues,
				"erl_id": erl_id,
				"provider": "aikido"
			}
		}
	}
}

# Test: No findings at all should pass compliance
test_no_findings if {
	vpm_05.compliant with input as {"findings": {}}
}

# Test: Empty issues array should pass compliance
test_empty_issues if {
	vpm_05.compliant with input as mock_input("E-VPM-10", [])
}

# Test: All issues closed should pass compliance
test_all_closed_issues if {
	issues := [
		{"id": 1, "status": "closed", "severity": "critical", "type": "open_source"},
		{"id": 2, "status": "closed", "severity": "high", "type": "sast"}
	]
	vpm_05.compliant with input as mock_input("E-VPM-10", issues)
}

# Test: Only medium and low severity open issues should pass compliance
test_medium_low_severity_passes if {
	issues := [
		{"id": 1, "status": "open", "severity": "medium", "type": "open_source"},
		{"id": 2, "status": "open", "severity": "low", "type": "cloud"}
	]
	vpm_05.compliant with input as mock_input("E-VPM-05", issues)
}

# Test: One open critical issue should fail compliance
test_open_critical_fails if {
	issues := [
		{"id": 1, "status": "open", "severity": "critical", "type": "open_source"}
	]
	not vpm_05.compliant with input as mock_input("E-VPM-10", issues)
}

# Test: One open high severity issue should fail compliance
test_open_high_fails if {
	issues := [
		{"id": 1, "status": "open", "severity": "high", "type": "sast"}
	]
	not vpm_05.compliant with input as mock_input("E-MNT-03", issues)
}

# Test: Snoozed and ignored high severity issues should pass compliance
test_snoozed_ignored_passes if {
	issues := [
		{"id": 1, "status": "snoozed", "severity": "critical", "type": "open_source"},
		{"id": 2, "status": "ignored", "severity": "high", "type": "sast"}
	]
	vpm_05.compliant with input as mock_input("E-VPM-10", issues)
}
