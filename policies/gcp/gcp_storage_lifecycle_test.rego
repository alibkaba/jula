package gcp.storage_lifecycle_test

import rego.v1
import data.gcp.storage_lifecycle

# Test case: Empty buckets list should pass compliance checks
test_empty_buckets if {
	storage_lifecycle.compliant with input as {
		"erl_id": "E-DCH-10",
		"finding": {
			"raw_data": []
		}
	}
}

# Test case: A standard, non-sensitive bucket (Pass)
test_non_sensitive_bucket_passes if {
	storage_lifecycle.compliant with input as {
		"erl_id": "E-DCH-10",
		"finding": {
			"raw_data": [
				{
					"name": "//storage.googleapis.com/jula-public-assets",
					"labels": {
						"data_class": "public"
					}
				}
			]
		}
	}
}

# Test case: A sensitive bucket with a valid Delete lifecycle rule (Pass)
test_sensitive_compliant_bucket_passes if {
	storage_lifecycle.compliant with input as {
		"erl_id": "E-DCH-10",
		"finding": {
			"raw_data": [
				{
					"name": "//storage.googleapis.com/jula-sensitive-ledger",
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
		}
	}
}

# Test case: A sensitive bucket with no lifecycle rules (Fail)
test_sensitive_non_compliant_missing_lifecycle_fails if {
	not storage_lifecycle.compliant with input as {
		"erl_id": "E-DCH-10",
		"finding": {
			"raw_data": [
				{
					"name": "//storage.googleapis.com/jula-sensitive-ledger",
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
		}
	}
}

# Test case: A sensitive bucket with a lifecycle rule, but action is not "Delete" (e.g. "SetStorageClass") (Fail)
test_sensitive_non_compliant_wrong_action_fails if {
	not storage_lifecycle.compliant with input as {
		"erl_id": "E-DCH-10",
		"finding": {
			"raw_data": [
				{
					"name": "//storage.googleapis.com/jula-sensitive-ledger",
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
		}
	}
}
