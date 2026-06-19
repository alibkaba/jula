package translators.gcp_storage

# Default rule to extract bucket data from drift-corrected payload
default result = []

result := [normalized |
    some i
    bucket := input.findings["EVID-gcp-storage"]["gcp"].raw_data.items[i]
    normalized := {
        "resource_id": bucket.id,
        "resource_name": bucket.name,
        "provider": "gcp",
        "service": "storage",
        "metadata": {
            "location": bucket.location,
            "storage_class": bucket.storageClass,
            "time_created": bucket.timeCreated,
            "last_updated": bucket.updated,
            "project_number": bucket.projectNumber
        },
        "configuration": {
            "versioning_enabled": object.get(bucket, "versioning", {"enabled": false}).enabled,
            "soft_delete_retention_seconds": object.get(bucket.softDeletePolicy, "retentionDurationSeconds", null),
            "iam": {
                "uniform_bucket_level_access": object.get(bucket.iamConfiguration.uniformBucketLevelAccess, "enabled", false),
                "public_access_prevention": object.get(bucket.iamConfiguration, "publicAccessPrevention", "unspecified")
            },
            "security": {
                "satisfies_pzi": object.get(bucket, "satisfiesPZI", false)
            }
        }
    }
]