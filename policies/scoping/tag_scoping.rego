package compliance.controls.tag_01

import rego.v1
import data.normalizers.core.gcp.storage as storage_norm

# Default compliance status
default compliant = false

control_id := "TAG-01"
customer_control_id := "CC-TAG-1"

# Check if GCS buckets meet the tag-scoping rule
compliant if {
	buckets := storage_norm.normalized
	all_buckets_compliant(buckets)
}

# Helper to verify if all buckets are compliant
all_buckets_compliant(buckets) if {
	count(buckets) == 0
}

all_buckets_compliant(buckets) if {
	count(buckets) > 0
	non_compliant_count := count([b |
		b := buckets[_]
		not bucket_is_compliant(b)
	])
	non_compliant_count == 0
}

# A bucket is compliant if it is not sensitive, OR if it is sensitive and has a CMEK key configured
bucket_is_compliant(normalized) if {
	not is_sensitive(normalized)
}

bucket_is_compliant(normalized) if {
	is_sensitive(normalized)
	has_cmek(normalized)
}

# Helper to identify sensitive data classification from resource tags/labels
is_sensitive(normalized) if {
	normalized.data_class == "sensitive"
}

is_sensitive(normalized) if {
	normalized.privacy == "gdpr"
}

# Helper to verify Customer-Managed Encryption Key (CMEK) configuration
has_cmek(normalized) if {
	normalized.has_cmek == true
}

# Dynamic details output
details := "Evaluation passed: all sensitive/GDPR storage buckets have Customer-Managed Encryption Keys configured" if {
	compliant
}

details := "Evaluation failed: sensitive/GDPR storage buckets detected without Customer-Managed Encryption Keys" if {
	not compliant
}
