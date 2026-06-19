package jula.rules

import rego.v1

default allow = false

allow if {
	input.provider == "gcp"
	input.resource.iamConfiguration.uniformBucketLevelAccess.enabled == true
}

violation contains {
	"msg": "Uniform bucket-level access must be enabled for GCP storage buckets.",
	"details": {
		"resource": input.resource.name,
		"field": "iamConfiguration.uniformBucketLevelAccess.enabled",
		"expected": true,
		"actual": input.resource.iamConfiguration.uniformBucketLevelAccess.enabled
	}
} if {
	input.provider == "gcp"
	input.resource.iamConfiguration.uniformBucketLevelAccess.enabled != true
}