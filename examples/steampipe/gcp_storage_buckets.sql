-- GCP Storage Bucket Encryption & Access Evidence
-- Controls: SC-28 (Protection of Information at Rest), SC-13 (Cryptographic Protection)
--
-- Collects encryption configuration, public access status, and retention
-- policies for all GCS buckets in the configured GCP project.

SELECT
  name                          AS bucket_name,
  project                       AS project_id,
  location                      AS region,
  storage_class,
  default_kms_key_name          AS kms_key,
  CASE
    WHEN default_kms_key_name IS NOT NULL THEN 'CMEK'
    ELSE 'Google-managed'
  END                           AS encryption_type,
  iam_configuration -> 'uniformBucketLevelAccess' ->> 'enabled'
                                AS uniform_access_enabled,
  iam_configuration -> 'publicAccessPrevention'
                                AS public_access_prevention,
  versioning ->> 'enabled'      AS versioning_enabled,
  retention_policy ->> 'retentionPeriod'
                                AS retention_period_seconds,
  logging ->> 'logBucket'       AS audit_log_bucket,
  time_created,
  updated
FROM
  gcp_storage_bucket
ORDER BY
  project, name;
