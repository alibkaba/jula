package compliance.scf.dch_10_test

import rego.v1
import data.compliance.scf.dch_10

# Helper to build mock input findings
mock_input(buckets) = {
	"findings": {
		"E-DCH-10": {
			"src-1": {
				"raw_data": buckets
			}
		}
	}
}

# Test case: Empty buckets list should pass compliance checks
test_empty_buckets if {
	dch_10.compliant with input as mock_input([])
}

# Test case: All buckets compliant (uniform access, public access prevention, and non-sensitive)
test_compliant_buckets if {
	buckets := [
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
			},
			"labels": {
				"data_class": "public"
			}
		}
	]
	dch_10.compliant with input as mock_input(buckets)
}

# Test case: Disabled uniform access should fail compliance
test_non_compliant_disabled_uniform if {
	buckets := [
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
			},
			"labels": {
				"data_class": "public"
			}
		}
	]
	not dch_10.compliant with input as mock_input(buckets)
}

# Test case: Missing public access prevention should fail
test_non_compliant_missing_prevention if {
	buckets := [
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
			},
			"labels": {
				"data_class": "public"
			}
		}
	]
	not dch_10.compliant with input as mock_input(buckets)
}

# Test case: Sensitive bucket with delete lifecycle passes
test_sensitive_compliant_bucket_passes if {
	buckets := [
		{
			"name": "//storage.googleapis.com/jula-sensitive-ledger",
			"resource": {
				"data": {
					"iamConfiguration": {
						"uniformBucketLevelAccess": {
							"enabled": true
						}
					},
					"publicAccessPrevention": "enforced"
				}
			},
			"labels": {
				"data_class": "sensitive"
			},
			"additionalAttributes": {
				"lifecycle": {
					"rule": [
						{
							"action": {
								"type": "Delete"
							}
						}
					]
				}
			}
		}
	]
	dch_10.compliant with input as mock_input(buckets)
}

# Test case: Sensitive bucket with no lifecycle fails
test_sensitive_non_compliant_missing_lifecycle_fails if {
	buckets := [
		{
			"name": "//storage.googleapis.com/jula-sensitive-ledger",
			"resource": {
				"data": {
					"iamConfiguration": {
						"uniformBucketLevelAccess": {
							"enabled": true
						}
					},
					"publicAccessPrevention": "enforced"
				}
			},
			"labels": {
				"data_class": "sensitive"
			},
			"additionalAttributes": {
				"lifecycle": {
					"rule": []
				}
			}
		}
	]
	not dch_10.compliant with input as mock_input(buckets)
}

# Test case: Sensitive bucket with non-delete lifecycle fails
test_sensitive_non_compliant_wrong_action_fails if {
	buckets := [
		{
			"name": "//storage.googleapis.com/jula-sensitive-ledger",
			"resource": {
				"data": {
					"iamConfiguration": {
						"uniformBucketLevelAccess": {
							"enabled": true
						}
					},
					"publicAccessPrevention": "enforced"
				}
			},
			"labels": {
				"data_class": "sensitive"
			},
			"additionalAttributes": {
				"lifecycle": {
					"rule": [
						{
							"action": {
								"type": "SetStorageClass"
							}
						}
					]
				}
			}
		}
	]
	not dch_10.compliant with input as mock_input(buckets)
}
