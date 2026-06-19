package translators.aws_s3

import rego.v1

# The translator normalizes the nested AWS S3 raw data into a flat, 
# predictable structure for consistent policy evaluation across the Jula Platform.

normalized := {
    "resource_id": bucket.Name,
    "arn": bucket.BucketArn,
    "creation_date": bucket.CreationDate,
    "owner_id": raw_data.listBuckets.Owner.ID,
    "public_access": {
        "block_public_acls": access_config.BlockPublicAcls,
        "ignore_public_acls": access_config.IgnorePublicAcls,
        "block_public_policy": access_config.BlockPublicPolicy,
        "restrict_public_buckets": access_config.RestrictPublicBuckets,
    },
    "encryption": {
        "sse_algorithm": sse_rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm,
        "bucket_key_enabled": sse_rule.BucketKeyEnabled,
    },
    "versioning_status": raw_data.versioning.Status,
} if {
    # Access the specific Jula evidence path
    raw_data := input.findings["EVID-aws-s3"]["aws"].raw_data
    
    # Extract bucket details (assuming single bucket per raw payload instance)
    bucket := raw_data.listBuckets.Buckets[_]
    
    # Extract nested configurations
    access_config := raw_data.publicAccessBlock.PublicAccessBlockConfiguration
    sse_rule := raw_data.encryption.ServerSideEncryptionConfiguration.Rules[_]
}