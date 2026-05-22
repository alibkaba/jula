package compliance.scf.vpm_10_test

import rego.v1
import data.compliance.scf.vpm_10

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

# Helper to build mock input with multiple ERLs
mock_input_multi(vpm10_issues, rsk03_issues) = {
	"findings": {
		"E-VPM-10": {
			"aikido_src": {
				"raw_data": vpm10_issues,
				"erl_id": "E-VPM-10",
				"provider": "aikido"
			}
		},
		"E-RSK-03": {
			"aikido_src": {
				"raw_data": rsk03_issues,
				"erl_id": "E-RSK-03",
				"provider": "aikido"
			}
		}
	}
}

# Test: No findings at all should pass compliance
test_no_findings if {
	vpm_10.compliant with input as {"findings": {}}
}

# Test: Empty issues array should pass compliance
test_empty_issues if {
	vpm_10.compliant with input as mock_input("E-VPM-10", [])
}

# Test: All issues closed should pass compliance
test_all_closed_issues if {
	issues := [
		{"id": 1, "status": "closed", "severity": "critical", "type": "cloud"},
		{"id": 2, "status": "closed", "severity": "high", "type": "iac"}
	]
	vpm_10.compliant with input as mock_input("E-VPM-10", issues)
}

# Test: Only medium and low severity open issues should pass compliance
test_medium_low_severity_passes if {
	issues := [
		{"id": 1, "status": "open", "severity": "medium", "type": "open_source"},
		{"id": 2, "status": "open", "severity": "low", "type": "sast"}
	]
	vpm_10.compliant with input as mock_input("E-VPM-10", issues)
}

# Test: One open critical issue should fail compliance
test_open_critical_fails if {
	issues := [
		{"id": 1, "status": "open", "severity": "critical", "type": "open_source"}
	]
	not vpm_10.compliant with input as mock_input("E-VPM-10", issues)
}

# Test: One open high severity issue should fail compliance
test_open_high_fails if {
	issues := [
		{"id": 1, "status": "open", "severity": "high", "type": "cloud_instance"}
	]
	not vpm_10.compliant with input as mock_input("E-RSK-04", issues)
}

# Test: Cross-ERL evaluation with critical in secondary ERL should fail
test_cross_erl_critical_fails if {
	vpm10 := [
		{"id": 1, "status": "closed", "severity": "critical", "type": "open_source"}
	]
	rsk03 := [
		{"id": 2, "status": "open", "severity": "high", "type": "cloud"}
	]
	not vpm_10.compliant with input as mock_input_multi(vpm10, rsk03)
}
