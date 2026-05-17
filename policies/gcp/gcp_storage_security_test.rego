package gcp.storage_security_test

import rego.v1
import data.gcp.storage_security

# Test case: Empty buckets list should pass compliance checks
test_empty_buckets if {
	storage_security.compliant with input as {
		"erl_id": "E-DCH-10",
		"finding": {
			"raw_data": []
		}
	}
}

# Test case: All buckets compliant should pass
test_compliant_buckets if {
	storage_security.compliant with input as {
		"erl_id": "E-DCH-10",
		"finding": {
			"raw_data": [
				{
					"name": "//storage.googleapis.com/jula-evidence-ledger",
					"resource": {
						"data": {
							"iamConfiguration": {
								"uniformBucketLevelAccess": {
									"enabled": true
								}
							},
							"publicAccessPrevention": "enforced"
						}
					}
				}
			]
		}
	}
}

# Test case: Disabled uniform access should fail compliance
test_non_compliant_disabled_uniform if {
	not storage_security.compliant with input as {
		"erl_id": "E-DCH-10",
		"finding": {
			"raw_data": [
				{
					"name": "//storage.googleapis.com/jula-evidence-ledger",
					"resource": {
						"data": {
							"iamConfiguration": {
								"uniformBucketLevelAccess": {
									"enabled": false
								}
							},
							"publicAccessPrevention": "enforced"
						}
					}
				}
			]
		}
	}
}

# Test case: Missing public access prevention should fail
test_non_compliant_missing_prevention if {
	not storage_security.compliant with input as {
		"erl_id": "E-DCH-10",
		"finding": {
			"raw_data": [
				{
					"name": "//storage.googleapis.com/jula-evidence-ledger",
					"resource": {
						"data": {
							"iamConfiguration": {
								"uniformBucketLevelAccess": {
									"enabled": true
								}
							},
							"publicAccessPrevention": "inherited"
						}
					}
				}
			]
		}
	}
}
