package compliance.scf.dch_10

import rego.v1

# Default compliance status
default compliant = false

# SCF metadata constants
scf_id := "DCH-10"
customer_control_id := "CC-2.1"

# Check if GCS bucket configs meet the required security standards (Uniform Access, Public Access Prevention, and Lifecycle)
compliant if {
	storage_checks := input.findings["storage"]
	every _, check in storage_checks {
		all_buckets_secured(check.normalized_data.buckets)
	}
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
	
	# Rule 3: Lifecycle compliance
	bucket_lifecycle_is_compliant(b)
}

# A bucket lifecycle is compliant if it's either non-sensitive OR sensitive with active delete lifecycle rules
bucket_lifecycle_is_compliant(b) if {
	not is_sensitive(b)
}

bucket_lifecycle_is_compliant(b) if {
	is_sensitive(b)
	has_delete_lifecycle(b)
}

# Helper to identify sensitive data classification
is_sensitive(b) if {
	b.labels.data_class == "sensitive"
}

# Helper to verify storage deletion limitation lifecycles
has_delete_lifecycle(b) if {
	# Ensure there is at least one lifecycle rule where action type is "Delete"
	rule := b.additionalAttributes.lifecycle.rule[_]
	rule.action.type == "Delete"
}
