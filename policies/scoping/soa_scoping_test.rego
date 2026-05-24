package compliance.controls.soa_01_test

import rego.v1
import data.compliance.controls.soa_01

# Test case 1: Control is out of scope (not in applicable_controls list) -> Should pass compliance
test_not_applicable_passes if {
	soa_01.compliant with input as {
		"metadata": {
			"soa": {
				"applicable_controls": ["DCH-10"]
			}
		}
	}
	soa_01.details == "Control is out of scope per Statement of Applicability" with input as {
		"metadata": {
			"soa": {
				"applicable_controls": ["DCH-10"]
			}
		}
	}
}

# Test case 2: Control is in scope, databases have SSL -> Should pass compliance
test_applicable_compliant if {
	mock_input := {
		"metadata": {
			"soa": {
				"applicable_controls": ["SOA-01"]
			}
		},
		"findings": {
			"EVID-GCP-INVENTORY": {
				"gcp": [
					{
						"resource": {
							"data": {
								"settings": {
									"ipConfiguration": {
										"requireSsl": true
									}
								}
							}
						}
					}
				]
			}
		}
	}
	soa_01.compliant with input as mock_input
	soa_01.details == "Evaluation successfully passed under policy package compliance.controls.soa_01" with input as mock_input
}

# Test case 3: Control is in scope, databases lack SSL -> Should fail compliance
test_applicable_non_compliant if {
	mock_input := {
		"metadata": {
			"soa": {
				"applicable_controls": ["SOA-01"]
			}
		},
		"findings": {
			"EVID-GCP-INVENTORY": {
				"gcp": [
					{
						"resource": {
							"data": {
								"settings": {
									"ipConfiguration": {
										"requireSsl": false
									}
								}
							}
						}
					}
				]
			}
		}
	}
	not soa_01.compliant with input as mock_input
	soa_01.details == "Evaluation failed: databases missing required SSL configuration" with input as mock_input
}
