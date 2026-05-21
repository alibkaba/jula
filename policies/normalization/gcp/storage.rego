package normalization.gcp.storage
import rego.v1

normalize(bucket) = normalized if {
	resource := object.get(bucket, "resource", {})
	res_data := object.get(resource, "data", {})
	iamConfiguration := object.get(res_data, "iamConfiguration", {})
	uniformBucketLevelAccess := object.get(iamConfiguration, "uniformBucketLevelAccess", {})
	encryption := object.get(res_data, "encryption", {})
	labels := object.get(bucket, "labels", {})
	additionalAttributes := object.get(bucket, "additionalAttributes", {})
	lifecycle := object.get(additionalAttributes, "lifecycle", {})
	rules := object.get(lifecycle, "rule", [])

	normalized := {
		"uniform_bucket_level_access": object.get(uniformBucketLevelAccess, "enabled", false) == true,
		"public_access_prevention": object.get(res_data, "publicAccessPrevention", ""),
		"data_class": object.get(labels, "data_class", ""),
		"privacy": object.get(labels, "privacy", ""),
		"has_cmek": object.get(encryption, "defaultKmsKeyName", "") != "",
		"has_delete_lifecycle": count([rule |
			rule := rules[_]
			action := object.get(rule, "action", {})
			object.get(action, "type", "") == "Delete"
		]) > 0
	}
}


