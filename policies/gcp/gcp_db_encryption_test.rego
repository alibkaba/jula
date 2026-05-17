package gcp.db_encryption_test

import rego.v1
import data.gcp.db_encryption

# Test case: Empty instances list should pass compliance checks
test_empty_instances if {
	db_encryption.compliant with input as {
		"erl_id": "E-BCM-16",
		"finding": {
			"raw_data": []
		}
	}
}

# Test case: All instances compliant should pass
test_compliant_instances if {
	db_encryption.compliant with input as {
		"erl_id": "E-BCM-16",
		"finding": {
			"raw_data": [
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
		}
	}
}

# Test case: Missing SSL configuration should fail compliance
test_non_compliant_missing_ssl if {
	not db_encryption.compliant with input as {
		"erl_id": "E-BCM-16",
		"finding": {
			"raw_data": [
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
		}
	}
}

# Test case: Missing disk encryption configuration should fail
test_non_compliant_missing_encryption if {
	not db_encryption.compliant with input as {
		"erl_id": "E-BCM-16",
		"finding": {
			"raw_data": [
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
		}
	}
}
