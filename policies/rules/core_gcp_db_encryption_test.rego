package compliance.controls.bcd_11_4_test

import rego.v1
import data.compliance.controls.bcd_11_4

# Helper to build mock input findings
mock_input(instances) = {
	"findings": {
		"EVID-GCP-INVENTORY": {
			"gcp": instances
		}
	}
}

# Test case: Empty instances list should pass compliance checks
test_empty_instances if {
	bcd_11_4.compliant with input as mock_input([])
}

# Test case: All instances compliant should pass
test_compliant_instances if {
	instances := [
		{
			"name": "//sqladmin.googleapis.com/projects/jula-494603/instances/prod-db",
			"resource": {
				"data": {
					"state": "RUNNING",
					"settings": {
						"ipConfiguration": {
							"requireSsl": true
						},
						"dataDiskEncryptionType": "PD_SSD"
					}
				}
			}
		}
	]
	bcd_11_4.compliant with input as mock_input(instances)
}

# Test case: Missing SSL configuration should fail compliance
test_non_compliant_missing_ssl if {
	instances := [
		{
			"name": "//sqladmin.googleapis.com/projects/jula-494603/instances/prod-db",
			"resource": {
				"data": {
					"state": "RUNNING",
					"settings": {
						"ipConfiguration": {
							"requireSsl": false
						},
						"dataDiskEncryptionType": "PD_SSD"
					}
				}
			}
		}
	]
	not bcd_11_4.compliant with input as mock_input(instances)
}

# Test case: Missing disk encryption configuration should fail
test_non_compliant_missing_encryption if {
	instances := [
		{
			"name": "//sqladmin.googleapis.com/projects/jula-494603/instances/prod-db",
			"resource": {
				"data": {
					"state": "RUNNING",
					"settings": {
						"ipConfiguration": {
							"requireSsl": true
						},
						"dataDiskEncryptionType": ""
					}
				}
			}
		}
	]
	not bcd_11_4.compliant with input as mock_input(instances)
}
