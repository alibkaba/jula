# Steampipe Evidence Collection Examples

Example SQL queries for collecting evidence from cloud providers using [Steampipe](https://steampipe.io/), which can then be signed with `jula-sign-evidence`.

## Workflow

```bash
# 1. Run Steampipe queries and export JSON
steampipe query --output json examples/steampipe/gcp_storage_buckets.sql > evidence/gcp_storage_buckets.json
steampipe query --output json examples/steampipe/gcp_iam_policies.sql > evidence/gcp_iam_policies.json
steampipe query --output json examples/steampipe/aws_s3_buckets.sql > evidence/aws_s3_buckets.json

# 2. Sign the collected evidence
jula-sign-evidence \
  --input ./evidence/ \
  --output gs://your-evidence-bucket/project-abc \
  --key-env JULA_SIGNING_KEY \
  --deployment-id production \
  --provider steampipe
```

## Queries

| File | Framework Controls | Description |
|:---|:---|:---|
| `gcp_storage_buckets.sql` | SC-28, SC-13 | Storage encryption and access controls |
| `gcp_iam_policies.sql` | AC-2, AC-6 | IAM bindings and role assignments |
| `aws_s3_buckets.sql` | SC-28, AC-3 | S3 encryption, versioning, and public access |
| `aws_cloudtrail.sql` | AU-2, AU-12 | CloudTrail logging configuration |

## Prerequisites

Install the relevant Steampipe plugins:

```bash
steampipe plugin install gcp
steampipe plugin install aws
```
