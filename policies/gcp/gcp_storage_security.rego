package compliance.scf.dch_10

import rego.v1
import data.normalization.gcp.storage as storage_norm

# Default compliance status
default compliant = false

# SCF metadata constants
scf_id := "DCH-10"
customer_control_id := "CC-2.1"

# Check if GCS bucket configs meet the required security standards
compliant if {
	buckets := storage_norm.normalized
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

# Core security rules for GCP Storage bucket using normalized properties
bucket_is_compliant(normalized) if {
	# Rule 1: Uniform bucket-level access is enabled
	normalized.uniform_bucket_level_access == true
	
	# Rule 2: Public Access Prevention is strictly enforced
	normalized.public_access_prevention == "enforced"
	
	# Rule 3: Lifecycle compliance
	bucket_lifecycle_is_compliant(normalized)
}

# A bucket lifecycle is compliant if it's either non-sensitive OR sensitive with active delete lifecycle rules
bucket_lifecycle_is_compliant(normalized) if {
	not is_sensitive(normalized)
}

bucket_lifecycle_is_compliant(normalized) if {
	is_sensitive(normalized)
	normalized.has_delete_lifecycle == true
}

# Helper to identify sensitive data classification
is_sensitive(normalized) if {
	normalized.data_class == "sensitive"
}

is_sensitive(normalized) if {
	normalized.privacy == "gdpr"
}
