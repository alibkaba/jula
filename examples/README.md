# Bring Your Own Collector (BYOC) Examples

The Jula Collector handles evidence extraction natively, but you can also collect evidence with any external tool and feed it into the Jula signing pipeline via `jula-sign-evidence`. These examples demonstrate two popular options: Steampipe and CloudQuery.

## Prerequisites

- `jula-sign-evidence` binary ([download from releases](https://github.com/alibkaba/jula/releases))
- An ECDSA signing key exported as `JULA_SIGNING_KEY`

## Steampipe

Example SQL queries for collecting evidence from cloud providers using [Steampipe](https://steampipe.io/).

### Workflow

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

### Queries

| File | Framework Controls | Description |
|:---|:---|:---|
| `steampipe/gcp_storage_buckets.sql` | SC-28, SC-13 | Storage encryption and access controls |
| `steampipe/gcp_iam_policies.sql` | AC-2, AC-6 | IAM bindings and role assignments |
| `steampipe/aws_s3_buckets.sql` | SC-28, AC-3 | S3 encryption, versioning, and public access |
| `steampipe/aws_cloudtrail.sql` | AU-2, AU-12 | CloudTrail logging configuration |

### Setup

```bash
steampipe plugin install gcp
steampipe plugin install aws
```

## CloudQuery

Example configurations for collecting evidence from cloud providers using [CloudQuery](https://www.cloudquery.io/).

### Workflow

```bash
# 1. Run CloudQuery sync to export JSON
cloudquery sync examples/cloudquery/gcp_sync.yml

# 2. Sign the collected evidence
jula-sign-evidence \
  --input ./evidence/ \
  --output gs://your-evidence-bucket/project-abc \
  --key-env JULA_SIGNING_KEY \
  --deployment-id production \
  --provider cloudquery
```

### Configurations

| File | Tables | Controls |
|:---|:---|:---|
| `cloudquery/gcp_sync.yml` | Storage buckets, IAM, KMS | SC-28, AC-2, SC-12 |
| `cloudquery/aws_sync.yml` | S3, CloudTrail, IAM | SC-28, AU-2, AC-2 |

### Setup

```bash
# Install CloudQuery CLI
brew install cloudquery/tap/cloudquery

# Plugins are auto-downloaded on first sync
```
