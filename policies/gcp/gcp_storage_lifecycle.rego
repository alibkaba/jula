package gcp.storage_lifecycle

import rego.v1

# Default compliance status
default compliant = false

# ERL ID this rule evaluates (reused from E-DCH-10)
erl_id := "E-DCH-10"

compliant if {
	input.erl_id == erl_id
	buckets := input.finding.raw_data
	all_buckets_compliant(buckets)
}

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

# A bucket is compliant if it's either non-sensitive OR sensitive with active delete lifecycle rules
bucket_is_compliant(b) if {
	not is_sensitive(b)
}

bucket_is_compliant(b) if {
	is_sensitive(b)
	has_delete_lifecycle(b)
}

# Helper to identify sensitive data classification (Decision A)
is_sensitive(b) if {
	b.labels.data_class == "sensitive"
}

# Helper to verify storage deletion limitation lifecycles (Decision B)
has_delete_lifecycle(b) if {
	# Ensure there is at least one lifecycle rule where action type is "Delete"
	rule := b.additionalAttributes.lifecycle.rule[_]
	rule.action.type == "Delete"
}
