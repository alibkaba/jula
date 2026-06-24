# CloudQuery Evidence Collection Examples

Example configurations for collecting evidence from cloud providers using [CloudQuery](https://www.cloudquery.io/), which can then be signed with `jula-sign-evidence`.

## Workflow

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

## Configurations

| File | Tables | Controls |
|:---|:---|:---|
| `gcp_sync.yml` | Storage buckets, IAM, KMS | SC-28, AC-2, SC-12 |
| `aws_sync.yml` | S3, CloudTrail, IAM | SC-28, AU-2, AC-2 |

## Prerequisites

Install CloudQuery and the relevant plugins:

```bash
# Install CloudQuery CLI
brew install cloudquery/tap/cloudquery

# Plugins are auto-downloaded on first sync
```
