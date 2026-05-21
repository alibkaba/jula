package compliance.scf.tag_01_test

import rego.v1
import data.compliance.scf.tag_01

# Helper to build mock input findings
mock_input(buckets) = {
	"findings": {
		"E-GCP-INVENTORY": {
			"gcp": buckets
		}
	}
}

# Test case 1: Bucket is non-sensitive (no sensitive tags) -> passes even without CMEK
test_non_sensitive_passes if {
	buckets := [
		{
			"name": "public-bucket",
			"labels": {
				"data_class": "public"
			},
			"resource": {
				"data": {
					"encryption": {
						"defaultKmsKeyName": ""
					}
				}
			}
		}
	]
	tag_01.compliant with input as mock_input(buckets)
	tag_01.details == "Evaluation passed: all sensitive/GDPR storage buckets have Customer-Managed Encryption Keys configured" with input as mock_input(buckets)
}

# Test case 2: Bucket is sensitive and has CMEK -> passes
test_sensitive_with_cmek_passes if {
	buckets := [
		{
			"name": "private-bucket",
			"labels": {
				"data_class": "sensitive"
			},
			"resource": {
				"data": {
					"encryption": {
						"defaultKmsKeyName": "projects/p1/locations/l1/keyRings/k1/cryptoKeys/key1"
					}
				}
			}
		}
	]
	tag_01.compliant with input as mock_input(buckets)
}

# Test case 3: Bucket is GDPR privacy scoped and has CMEK -> passes
test_gdpr_with_cmek_passes if {
	buckets := [
		{
			"name": "gdpr-bucket",
			"labels": {
				"privacy": "gdpr"
			},
			"resource": {
				"data": {
					"encryption": {
						"defaultKmsKeyName": "projects/p1/locations/l1/keyRings/k1/cryptoKeys/key1"
					}
				}
			}
		}
	]
	tag_01.compliant with input as mock_input(buckets)
}

# Test case 4: Bucket is sensitive but has NO CMEK -> fails
test_sensitive_without_cmek_fails if {
	buckets := [
		{
			"name": "private-bucket",
			"labels": {
				"data_class": "sensitive"
			},
			"resource": {
				"data": {
					"encryption": {
						"defaultKmsKeyName": ""
					}
				}
			}
		}
	]
	not tag_01.compliant with input as mock_input(buckets)
	tag_01.details == "Evaluation failed: sensitive/GDPR storage buckets detected without Customer-Managed Encryption Keys" with input as mock_input(buckets)
}
