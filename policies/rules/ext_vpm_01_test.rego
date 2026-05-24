package compliance.controls.vpm_01_test

import rego.v1
import data.compliance.controls.vpm_01

# Helper to build mock input with a single Dataset source
mock_input(issues) = {
	"findings": {
		"EVID-VPM-01": {
			"aikido_src": {
				"raw_data": issues,
				"evidence_id": "EVID-VPM-01",
				"provider": "aikido"
			}
		}
	}
}

# Helper to build mock input with multiple Datasets
mock_input_multi(vpm01_issues, mnt03_issues) = {
	"findings": {
		"EVID-VPM-01": {
			"aikido_src": {
				"raw_data": vpm01_issues,
				"evidence_id": "EVID-VPM-01",
				"provider": "aikido"
			}
		},
		"EVID-MNT-03": {
			"aikido_src": {
				"raw_data": mnt03_issues,
				"evidence_id": "EVID-MNT-03",
				"provider": "aikido"
			}
		}
	}
}

# Test: No findings at all should pass compliance
test_no_findings if {
	vpm_01.compliant with input as {"findings": {}}
}

# Test: Empty issues array should pass compliance
test_empty_issues if {
	vpm_01.compliant with input as mock_input([])
}

# Test: All issues closed should pass compliance
test_all_closed_issues if {
	issues := [
		{"id": 1, "status": "closed", "severity": "critical", "type": "open_source"},
		{"id": 2, "status": "closed", "severity": "high", "type": "open_source"}
	]
	vpm_01.compliant with input as mock_input(issues)
}

# Test: Only medium and low severity open issues should pass compliance
test_medium_low_severity_passes if {
	issues := [
		{"id": 1, "status": "open", "severity": "medium", "type": "open_source"},
		{"id": 2, "status": "open", "severity": "low", "type": "open_source"}
	]
	vpm_01.compliant with input as mock_input(issues)
}

# Test: One open critical issue should fail compliance
test_open_critical_fails if {
	issues := [
		{"id": 1, "status": "open", "severity": "critical", "type": "open_source"},
		{"id": 2, "status": "closed", "severity": "high", "type": "open_source"}
	]
	not vpm_01.compliant with input as mock_input(issues)
}

# Test: One open high severity issue should fail compliance
test_open_high_fails if {
	issues := [
		{"id": 1, "status": "closed", "severity": "critical", "type": "open_source"},
		{"id": 2, "status": "open", "severity": "high", "type": "open_source"}
	]
	not vpm_01.compliant with input as mock_input(issues)
}

# Test: Mixed statuses with no open critical/high should pass
test_mixed_statuses_passes if {
	issues := [
		{"id": 1, "status": "ignored", "severity": "critical", "type": "open_source"},
		{"id": 2, "status": "snoozed", "severity": "high", "type": "open_source"},
		{"id": 3, "status": "open", "severity": "medium", "type": "sast"}
	]
	vpm_01.compliant with input as mock_input(issues)
}

# Test: Critical issue in secondary Dataset (EVID-MNT-03) should fail compliance
test_cross_erl_critical_fails if {
	vpm01 := [
		{"id": 1, "status": "closed", "severity": "critical", "type": "open_source"}
	]
	mnt03 := [
		{"id": 2, "status": "open", "severity": "critical", "type": "open_source"}
	]
	not vpm_01.compliant with input as mock_input_multi(vpm01, mnt03)
}
