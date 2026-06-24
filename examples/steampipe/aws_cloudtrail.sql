-- AWS CloudTrail Logging Evidence
-- Controls: AU-2 (Event Logging), AU-12 (Audit Record Generation)
--
-- Collects CloudTrail configuration including multi-region status,
-- log validation, encryption, and event selectors.

SELECT
  name                          AS trail_name,
  home_region,
  account_id,
  is_multi_region_trail,
  is_logging,
  log_file_validation_enabled,
  kms_key_id,
  s3_bucket_name                AS log_bucket,
  cloud_watch_logs_log_group_arn AS cloudwatch_log_group,
  include_global_service_events,
  has_custom_event_selectors,
  has_insight_selectors
FROM
  aws_cloudtrail_trail
WHERE
  region = home_region
ORDER BY
  account_id, name;
