-- GCP IAM Policy Bindings Evidence
-- Controls: AC-2 (Account Management), AC-6 (Least Privilege)
--
-- Collects IAM policy bindings for the configured GCP project,
-- including role assignments, member identities, and conditions.

SELECT
  project                       AS project_id,
  entity                        AS resource,
  role,
  member,
  CASE
    WHEN member LIKE 'user:%'           THEN 'user'
    WHEN member LIKE 'serviceAccount:%' THEN 'service_account'
    WHEN member LIKE 'group:%'          THEN 'group'
    WHEN member LIKE 'domain:%'         THEN 'domain'
    ELSE 'other'
  END                           AS member_type,
  CASE
    WHEN role LIKE '%admin%'    THEN 'elevated'
    WHEN role LIKE '%owner%'    THEN 'elevated'
    WHEN role LIKE '%editor%'   THEN 'elevated'
    ELSE 'standard'
  END                           AS privilege_level
FROM
  gcp_iam_policy,
  jsonb_array_elements(bindings) AS binding,
  jsonb_array_elements_text(binding -> 'members') AS member,
  LATERAL (SELECT binding ->> 'role' AS role) AS r
ORDER BY
  privilege_level DESC, role, member;
