package gcp.storage_security

import rego.v1

# Default compliance status
default compliant = false

# ERL ID this rule evaluates
erl_id := "E-DCH-10"

# Check if GCS bucket configs meet the required security standards
compliant if {
	# Ensure the input represents the target ERL ID
	input.erl_id == erl_id
	
	# Decode the raw payload
	buckets := input.finding.raw_data
	
	# Verify that every bucket in the list is fully secured
	all_buckets_secured(buckets)
}

# Helper to verify if all buckets are secured
all_buckets_secured(buckets) if {
	count(buckets) == 0
}

all_buckets_secured(buckets) if {
	count(buckets) > 0
	# Every bucket in the payload must be compliant
	non_compliant_count := count([b |
		b := buckets[_]
		not bucket_is_compliant(b)
	])
	non_compliant_count == 0
}

# Core security rules for GCP Storage bucket
bucket_is_compliant(b) if {
	# Rule 1: Uniform bucket-level access is enabled
	b.resource.data.iamConfiguration.uniformBucketLevelAccess.enabled == true
	
	# Rule 2: Public Access Prevention is strictly enforced
	b.resource.data.publicAccessPrevention == "enforced"
}
