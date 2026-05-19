package compliance.scf.tag_01

import rego.v1

# Default compliance status
default compliant = false

scf_id := "TAG-01"
customer_control_id := "CC-TAG-1"

# Check if GCS buckets meet the tag-scoping rule
compliant if {
	storage_checks := input.findings["storage"]
	every _, check in storage_checks {
		all_buckets_compliant(check.normalized_data.buckets)
	}
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
bucket_is_compliant(b) if {
	not is_sensitive(b)
}

bucket_is_compliant(b) if {
	is_sensitive(b)
	has_cmek(b)
}

# Helper to identify sensitive data classification from resource tags/labels
is_sensitive(b) if {
	b.labels.data_class == "sensitive"
}

is_sensitive(b) if {
	b.labels.privacy == "gdpr"
}

# Helper to verify Customer-Managed Encryption Key (CMEK) configuration
has_cmek(b) if {
	b.resource.data.encryption.defaultKmsKeyName != ""
}

# Dynamic details output
details := "Evaluation passed: all sensitive/GDPR storage buckets have Customer-Managed Encryption Keys configured" if {
	compliant
}

details := "Evaluation failed: sensitive/GDPR storage buckets detected without Customer-Managed Encryption Keys" if {
	not compliant
}
