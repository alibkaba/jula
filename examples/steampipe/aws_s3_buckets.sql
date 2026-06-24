-- AWS S3 Bucket Encryption & Public Access Evidence
-- Controls: SC-28 (Protection of Information at Rest), AC-3 (Access Enforcement)
--
-- Collects encryption, versioning, public access block, and logging
-- configuration for all S3 buckets in the configured AWS account.

SELECT
  name                          AS bucket_name,
  account_id,
  region,
  server_side_encryption_configuration -> 'Rules' -> 0
    -> 'ApplyServerSideEncryptionByDefault' ->> 'SSEAlgorithm'
                                AS encryption_algorithm,
  server_side_encryption_configuration -> 'Rules' -> 0
    -> 'ApplyServerSideEncryptionByDefault' ->> 'KMSMasterKeyID'
                                AS kms_key_id,
  CASE
    WHEN server_side_encryption_configuration IS NOT NULL THEN 'enabled'
    ELSE 'disabled'
  END                           AS encryption_status,
  versioning ->> 'Status'       AS versioning_status,
  block_public_acls             AS block_public_acls,
  block_public_policy           AS block_public_policy,
  ignore_public_acls            AS ignore_public_acls,
  restrict_public_buckets       AS restrict_public_buckets,
  logging ->> 'TargetBucket'    AS audit_log_bucket,
  creation_date
FROM
  aws_s3_bucket
ORDER BY
  account_id, name;
