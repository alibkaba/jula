#!/usr/bin/env bash
# ============================================================================
# verify.sh — Validate Jula Infrastructure State
# ============================================================================
# Usage:   ./scripts/infra-verify.sh [aws|gcp]
# ============================================================================

show_help() {
  cat <<'HELP'
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  verify.sh — Validate Jula Infrastructure State
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  USAGE
    ./scripts/infra-verify.sh <aws|gcp>

  PREREQUISITES
    • Authenticated to target cloud
    • terraform.tfvars populated at deploy/terraform/<env>/

  WHAT IT DOES
    1. Auto-detects mode (standup or teardown) from Terraform state
    2. In standup mode: verifies all resources exist and are healthy
    3. In teardown mode: verifies resources are destroyed, bootstrap survived
    4. Outputs a human-readable checklist to the terminal
    5. Writes a machine-readable JSON report to ops/<deployment_id>/
    6. Uploads the JSON report to the evidence bucket

  RESOURCES CHECKED
    Compute:    Cloud Run / ECS cluster + task definitions
    Registry:   Artifact Registry / ECR repositories
    Secrets:    Secret Manager / Secrets Manager entries
    Scheduler:  Cloud Scheduler / EventBridge schedules
    IAM:        Service accounts / IAM roles
    Storage:    Evidence bucket, apply logs, ops archives
    CI/CD:      CI/CD SA/role, WIF/OIDC provider (Terraform-managed)

  AFTER THIS
    If standup: ./scripts/test-e2e-cloud.sh   Run live smoke test
    If teardown: All done. Ops artifacts preserved in bucket.

  IF IT FAILS
    • Check which resource failed and compare against Terraform state
    • Re-run ./scripts/infra-standup.sh <env> to recreate missing resources
    • Bootstrap failures indicate manual setup was skipped
HELP
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  show_help
  exit 0
fi

ENV=${1:-}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

validate_env
preflight_check

PASS=0
FAIL=0
CHECKS_JSON=""

# Record a check result for both terminal output and JSON report.
# Usage: record_check <category> <resource_name> <status:pass|fail> <identifier_or_null> <message>
record_check() {
  local category="$1"
  local resource_name="$2"
  local status="$3"
  local identifier="$4"
  local message="$5"

  if [ "$status" == "pass" ]; then
    echo "  ✅ $message"
    PASS=$((PASS + 1))
  else
    echo "  ❌ $message"
    FAIL=$((FAIL + 1))
  fi

  # Format identifier as JSON string or null
  local id_json
  if [ "$identifier" == "null" ] || [ -z "$identifier" ]; then
    id_json="null"
  else
    id_json="\"$(echo "$identifier" | sed 's/"/\\"/g')\"" 
  fi

  local entry="{\"category\":\"$category\",\"resource\":\"$resource_name\",\"status\":\"$status\",\"identifier\":$id_json}"

  if [ -z "$CHECKS_JSON" ]; then
    CHECKS_JSON="$entry"
  else
    CHECKS_JSON="$CHECKS_JSON,$entry"
  fi
}



# --- Read config from tfvars ---
BUCKET_NAME=$(grep 'evidence_bucket_name' "deploy/terraform/$ENV/terraform.tfvars" | head -n 1 | awk -F'"' '{print $2}')

if [ "$ENV" == "gcp" ]; then
  PROJECT_ID=$(grep 'project_id' "deploy/terraform/$ENV/terraform.tfvars" | head -n 1 | awk -F'"' '{print $2}')
fi
if [ "$ENV" == "aws" ]; then
  AWS_REGION=$(grep 'aws_region' "deploy/terraform/$ENV/terraform.tfvars" | head -n 1 | awk -F'"' '{print $2}')
  AWS_REGION=${AWS_REGION:-us-east-1}
fi

# --- Detect mode from Terraform state ---
RESOURCE_COUNT=$(tf state list 2>/dev/null | wc -l | tr -d ' ')

if [ "$RESOURCE_COUNT" -gt 0 ]; then
  MODE="standup"
  DEPLOYMENT_ID=$(extract_deployment_id)
else
  MODE="teardown"
  DEPLOYMENT_ID=""
fi

echo ""
echo "[VERIFY] Mode: $MODE${DEPLOYMENT_ID:+ (deployment: $DEPLOYMENT_ID)}"
echo ""

# ============================================================================
# STANDUP VERIFICATION
# ============================================================================
verify_standup_gcp() {
  # Cloud Run services
  for SVC in jula-collector jula-assessor; do
    STATUS=$(gcloud_cli run services describe "$SVC" \
      --project="$PROJECT_ID" --region=us-central1 \
      --format="value(status.conditions[0].status)" 2>/dev/null)
    SVC_URI=$(gcloud_cli run services describe "$SVC" \
      --project="$PROJECT_ID" --region=us-central1 \
      --format="value(status.url)" 2>/dev/null || echo "")
    if [ "$STATUS" == "True" ]; then
      record_check "compute" "$SVC" "pass" "${SVC_URI:-null}" "Cloud Run: $SVC is serving"
    else
      record_check "compute" "$SVC" "fail" "null" "Cloud Run: $SVC not ready (status: ${STATUS:-not found})"
    fi
  done

  # Secrets
  for SECRET in jula-signing-key jula-public-key jula-source-token jula-dispatch-token; do
    if gcloud_cli secrets versions access latest --secret="$SECRET" --project="$PROJECT_ID" &>/dev/null; then
      record_check "secret" "$SECRET" "pass" "projects/$PROJECT_ID/secrets/$SECRET" "Secret: $SECRET accessible"
    else
      record_check "secret" "$SECRET" "fail" "null" "Secret: $SECRET not accessible"
    fi
  done

  # Scheduler jobs
  for JOB in jula-daily-evidence-collection jula-daily-evidence-assessment; do
    STATE=$(gcloud_cli scheduler jobs describe "$JOB" \
      --project="$PROJECT_ID" --location=us-central1 \
      --format="value(state)" 2>/dev/null)
    if [ "$STATE" == "ENABLED" ]; then
      record_check "scheduler" "$JOB" "pass" "projects/$PROJECT_ID/locations/us-central1/jobs/$JOB" "Scheduler: $JOB is ENABLED"
    else
      record_check "scheduler" "$JOB" "fail" "null" "Scheduler: $JOB not enabled (state: ${STATE:-not found})"
    fi
  done

  # Evidence bucket
  if gsutil_cli ls "gs://$BUCKET_NAME" &>/dev/null; then
    record_check "storage" "$BUCKET_NAME" "pass" "gs://$BUCKET_NAME" "Bucket: $BUCKET_NAME exists"
  else
    record_check "storage" "$BUCKET_NAME" "fail" "null" "Bucket: $BUCKET_NAME not found"
  fi

  # Apply log
  if [ -n "$DEPLOYMENT_ID" ]; then
    if gsutil_cli ls "gs://$BUCKET_NAME/deploy-${DEPLOYMENT_ID}/terraform/apply.log" &>/dev/null; then
      record_check "storage" "apply-log" "pass" "gs://$BUCKET_NAME/deploy-${DEPLOYMENT_ID}/terraform/apply.log" "Bucket: apply.log uploaded"
    else
      record_check "storage" "apply-log" "fail" "null" "Bucket: apply.log not found at deploy-${DEPLOYMENT_ID}/terraform/"
    fi
  fi

  # Service accounts
  if gcloud_cli iam service-accounts describe "jula-runner@${PROJECT_ID}.iam.gserviceaccount.com" --project="$PROJECT_ID" &>/dev/null; then
    record_check "iam" "jula-runner" "pass" "jula-runner@${PROJECT_ID}.iam.gserviceaccount.com" "SA: jula-runner exists"
  else
    record_check "iam" "jula-runner" "fail" "null" "SA: jula-runner not found"
  fi

  # CI/CD resources (Terraform-managed, destroyed on teardown)
  if gcloud_cli iam service-accounts describe "jula-cicd-sa@${PROJECT_ID}.iam.gserviceaccount.com" --project="$PROJECT_ID" &>/dev/null; then
    record_check "iam" "jula-cicd-sa" "pass" "jula-cicd-sa@${PROJECT_ID}.iam.gserviceaccount.com" "IAM: jula-cicd-sa exists"
  else
    record_check "iam" "jula-cicd-sa" "fail" "null" "IAM: jula-cicd-sa not found"
  fi

  WIF_POOL=$(gcloud_cli iam workload-identity-pools list --location global --project="$PROJECT_ID" --format="value(name)" 2>/dev/null | grep github-actions || echo "")
  if [ -n "$WIF_POOL" ]; then
    record_check "iam" "github-actions-pool" "pass" "$WIF_POOL" "IAM: WIF pool exists (github-actions-pool)"
  else
    record_check "iam" "github-actions-pool" "fail" "null" "IAM: WIF pool not found"
  fi

  # Artifact Registry
  for REPO in jula-collector jula-assessor; do
    if gcloud_cli artifacts repositories describe "$REPO" --project="$PROJECT_ID" --location=us-central1 &>/dev/null; then
      record_check "registry" "$REPO" "pass" "us-central1-docker.pkg.dev/$PROJECT_ID/$REPO" "Artifact Registry: $REPO exists"
    else
      record_check "registry" "$REPO" "fail" "null" "Artifact Registry: $REPO not found"
    fi
  done

  # ---- Networking Checks ----
  echo ""
  echo "  🔗 Networking"

  # VPC
  VPC_STATE=$(gcloud_cli compute networks describe jula-vpc \
    --project="$PROJECT_ID" --format="value(name)" 2>/dev/null || echo "missing")
  if [ "$VPC_STATE" == "jula-vpc" ]; then
    record_check "networking" "vpc" "pass" "jula-vpc" "Networking: VPC jula-vpc exists"
  else
    record_check "networking" "vpc" "fail" "null" "Networking: VPC jula-vpc not found"
  fi

  # Subnet
  SUBNET_STATE=$(gcloud_cli compute networks subnets describe jula-subnet \
    --project="$PROJECT_ID" --region=us-central1 --format="value(name)" 2>/dev/null || echo "missing")
  if [ "$SUBNET_STATE" == "jula-subnet" ]; then
    record_check "networking" "subnet" "pass" "jula-subnet" "Networking: Subnet jula-subnet exists"
  else
    record_check "networking" "subnet" "fail" "null" "Networking: Subnet jula-subnet not found"
  fi

  # Cloud NAT
  NAT_STATE=$(gcloud_cli compute routers nats describe jula-nat \
    --router=jula-router --project="$PROJECT_ID" --region=us-central1 \
    --format="value(name)" 2>/dev/null || echo "missing")
  if [ "$NAT_STATE" == "jula-nat" ]; then
    record_check "networking" "cloud-nat" "pass" "jula-nat" "Networking: Cloud NAT jula-nat exists"
  else
    record_check "networking" "cloud-nat" "fail" "null" "Networking: Cloud NAT jula-nat not found"
  fi

  # Firewall rules
  for FW_RULE in jula-deny-all-egress jula-allow-github-egress jula-allow-google-apis-egress; do
    FW_STATE=$(gcloud_cli compute firewall-rules describe "$FW_RULE" \
      --project="$PROJECT_ID" --format="value(name)" 2>/dev/null || echo "missing")
    if [ "$FW_STATE" == "$FW_RULE" ]; then
      record_check "networking" "$FW_RULE" "pass" "$FW_RULE" "Networking: Firewall $FW_RULE exists"
    else
      record_check "networking" "$FW_RULE" "fail" "null" "Networking: Firewall $FW_RULE not found"
    fi
  done

  # ---- Security Hardening Checks ----
  echo ""
  echo "  🔒 Security"

  # Cloud Run ingress restriction
  for SVC in jula-collector jula-assessor; do
    INGRESS=$(gcloud_cli run services describe "$SVC" \
      --project="$PROJECT_ID" --region=us-central1 \
      --format="value(spec.template.metadata.annotations['run.googleapis.com/ingress'])" 2>/dev/null)
    if [ "$INGRESS" == "internal-and-cloud-load-balancing" ] || [ "$INGRESS" == "internal" ]; then
      record_check "security" "${SVC}-ingress" "pass" "$INGRESS" "Security: $SVC ingress restricted ($INGRESS)"
    else
      record_check "security" "${SVC}-ingress" "fail" "${INGRESS:-not set}" "Security: $SVC ingress is OPEN (${INGRESS:-INGRESS_TRAFFIC_ALL})"
    fi
  done

  # Cloud Run IAM — no allUsers
  for SVC in jula-collector jula-assessor; do
    IAM_POLICY=$(gcloud_cli run services get-iam-policy "$SVC" \
      --project="$PROJECT_ID" --region=us-central1 \
      --format="json" 2>/dev/null)
    if echo "$IAM_POLICY" | grep -q "allUsers"; then
      record_check "security" "${SVC}-iam" "fail" "allUsers" "Security: $SVC allows unauthenticated invocation (allUsers)"
    else
      record_check "security" "${SVC}-iam" "pass" "authenticated-only" "Security: $SVC requires authentication"
    fi
  done

  # Evidence bucket access logging
  LOG_BUCKET=$(gsutil_cli logging get "gs://$BUCKET_NAME" 2>/dev/null | grep logBucket | awk '{print $2}' || echo "")
  if [ -n "$LOG_BUCKET" ]; then
    record_check "security" "bucket-logging" "pass" "$LOG_BUCKET" "Security: Evidence bucket access logging enabled"
  else
    record_check "security" "bucket-logging" "fail" "null" "Security: Evidence bucket has no access logging"
  fi
}

# ============================================================================
# TEARDOWN VERIFICATION
# ============================================================================
verify_teardown_gcp() {
  # Cloud Run services should be gone
  for SVC in jula-collector jula-assessor; do
    if gcloud_cli run services describe "$SVC" --project="$PROJECT_ID" --region=us-central1 &>/dev/null; then
      record_check "compute" "$SVC" "fail" "$SVC" "Cloud Run: $SVC still exists (should be destroyed)"
    else
      record_check "compute" "$SVC" "pass" "null" "Cloud Run: $SVC destroyed"
    fi
  done

  # Artifact Registry should be gone
  for REPO in jula-collector jula-assessor; do
    if gcloud_cli artifacts repositories describe "$REPO" --project="$PROJECT_ID" --location=us-central1 &>/dev/null; then
      record_check "registry" "$REPO" "fail" "$REPO" "Artifact Registry: $REPO still exists (should be destroyed)"
    else
      record_check "registry" "$REPO" "pass" "null" "Artifact Registry: $REPO destroyed"
    fi
  done

  # Secrets should be gone
  for SECRET in jula-signing-key jula-public-key jula-source-token jula-dispatch-token; do
    if gcloud_cli secrets describe "$SECRET" --project="$PROJECT_ID" &>/dev/null; then
      record_check "secret" "$SECRET" "fail" "$SECRET" "Secret: $SECRET still exists (should be destroyed)"
    else
      record_check "secret" "$SECRET" "pass" "null" "Secret: $SECRET destroyed"
    fi
  done

  # Scheduler jobs should be gone
  for JOB in jula-daily-evidence-collection jula-daily-evidence-assessment; do
    if gcloud_cli scheduler jobs describe "$JOB" --project="$PROJECT_ID" --location=us-central1 &>/dev/null; then
      record_check "scheduler" "$JOB" "fail" "$JOB" "Scheduler: $JOB still exists (should be destroyed)"
    else
      record_check "scheduler" "$JOB" "pass" "null" "Scheduler: $JOB destroyed"
    fi
  done

  # jula-runner SA should be gone
  if gcloud_cli iam service-accounts describe "jula-runner@${PROJECT_ID}.iam.gserviceaccount.com" --project="$PROJECT_ID" &>/dev/null; then
    record_check "iam" "jula-runner" "fail" "jula-runner@${PROJECT_ID}.iam.gserviceaccount.com" "SA: jula-runner still exists (should be destroyed)"
  else
    record_check "iam" "jula-runner" "pass" "null" "SA: jula-runner destroyed"
  fi

  # CI/CD resources (Terraform-managed, should be destroyed)
  if gcloud_cli iam service-accounts describe "jula-cicd-sa@${PROJECT_ID}.iam.gserviceaccount.com" --project="$PROJECT_ID" &>/dev/null; then
    record_check "iam" "jula-cicd-sa" "fail" "jula-cicd-sa@${PROJECT_ID}.iam.gserviceaccount.com" "IAM: jula-cicd-sa still exists (should be destroyed)"
  else
    record_check "iam" "jula-cicd-sa" "pass" "null" "IAM: jula-cicd-sa destroyed"
  fi

  WIF_POOL=$(gcloud_cli iam workload-identity-pools list --location global --project="$PROJECT_ID" --format="value(name)" 2>/dev/null | grep github-actions || echo "")
  if [ -n "$WIF_POOL" ]; then
    record_check "iam" "github-actions-pool" "fail" "$WIF_POOL" "IAM: WIF pool still exists (should be destroyed)"
  else
    record_check "iam" "github-actions-pool" "pass" "null" "IAM: WIF pool destroyed"
  fi

  # Evidence bucket should survive
  if gsutil_cli ls "gs://$BUCKET_NAME" &>/dev/null; then
    record_check "storage" "$BUCKET_NAME" "pass" "gs://$BUCKET_NAME" "Bucket: $BUCKET_NAME survived"
  else
    record_check "storage" "$BUCKET_NAME" "fail" "null" "Bucket: $BUCKET_NAME missing (should be permanent)"
  fi

  # Terraform ops artifacts should exist in bucket
  ARCHIVE_COUNT=$(gsutil_cli ls "gs://$BUCKET_NAME/deploy-*/terraform/" 2>/dev/null | wc -l | tr -d ' ' || echo "0")
  if [ "$ARCHIVE_COUNT" -gt 0 ]; then
    record_check "storage" "terraform-ops" "pass" "gs://$BUCKET_NAME/deploy-*/terraform/" "Archive: $ARCHIVE_COUNT ops files preserved"
  else
    record_check "storage" "terraform-ops" "fail" "null" "Archive: terraform/ ops folder is empty or missing"
  fi
}

# ============================================================================
# AWS STANDUP VERIFICATION
# ============================================================================
verify_standup_aws() {
  # ECS cluster
  CLUSTER_STATUS=$(aws_cli ecs describe-clusters --clusters jula-cluster \
    --query "clusters[0].status" --output text 2>/dev/null)
  CLUSTER_ARN=$(aws_cli ecs describe-clusters --clusters jula-cluster \
    --query "clusters[0].clusterArn" --output text 2>/dev/null || echo "")
  if [ "$CLUSTER_STATUS" == "ACTIVE" ]; then
    record_check "compute" "jula-cluster" "pass" "${CLUSTER_ARN:-null}" "ECS: jula-cluster is ACTIVE"
  else
    record_check "compute" "jula-cluster" "fail" "null" "ECS: jula-cluster not active (status: ${CLUSTER_STATUS:-not found})"
  fi

  # Task definitions
  for FAMILY in jula-collector jula-assessor; do
    TD_ARN=$(aws_cli ecs list-task-definitions --family-prefix "$FAMILY" \
      --query "taskDefinitionArns[-1]" --output text 2>/dev/null || echo "")
    if [ -n "$TD_ARN" ] && [ "$TD_ARN" != "None" ]; then
      record_check "compute" "$FAMILY" "pass" "$TD_ARN" "ECS: $FAMILY task definition registered"
    else
      record_check "compute" "$FAMILY" "fail" "null" "ECS: $FAMILY task definition not found"
    fi
  done

  # ECR repositories
  for REPO in jula-collector jula-assessor; do
    REPO_URI=$(aws_cli ecr describe-repositories --repository-names "$REPO" \
      --query "repositories[0].repositoryUri" --output text 2>/dev/null || echo "")
    if [ -n "$REPO_URI" ] && [ "$REPO_URI" != "None" ]; then
      record_check "registry" "$REPO" "pass" "$REPO_URI" "ECR: $REPO exists"
    else
      record_check "registry" "$REPO" "fail" "null" "ECR: $REPO not found"
    fi
  done

  # Secrets
  for SECRET in jula-signing-key jula-public-key jula-source-token jula-dispatch-token; do
    SECRET_ARN=$(aws_cli secretsmanager describe-secret --secret-id "$SECRET" \
      --query "ARN" --output text 2>/dev/null || echo "")
    if [ -n "$SECRET_ARN" ] && [ "$SECRET_ARN" != "None" ]; then
      record_check "secret" "$SECRET" "pass" "$SECRET_ARN" "Secret: $SECRET accessible"
    else
      record_check "secret" "$SECRET" "fail" "null" "Secret: $SECRET not accessible"
    fi
  done

  # EventBridge Scheduler schedules
  for SCHEDULE in jula-daily-evidence-collection jula-daily-evidence-assessment; do
    SCHEDULE_STATE=$(aws_cli scheduler get-schedule --name "$SCHEDULE" \
      --query "State" --output text 2>/dev/null || echo "")
    SCHEDULE_ARN=$(aws_cli scheduler get-schedule --name "$SCHEDULE" \
      --query "Arn" --output text 2>/dev/null || echo "")
    if [ "$SCHEDULE_STATE" == "ENABLED" ]; then
      record_check "scheduler" "$SCHEDULE" "pass" "${SCHEDULE_ARN:-null}" "Scheduler: $SCHEDULE is ENABLED"
    else
      record_check "scheduler" "$SCHEDULE" "fail" "null" "Scheduler: $SCHEDULE not enabled (state: ${SCHEDULE_STATE:-not found})"
    fi
  done

  # IAM roles
  for ROLE in jula-ecs-execution-role jula-ecs-task-role jula-scheduler-role; do
    ROLE_ARN=$(aws_cli iam get-role --role-name "$ROLE" \
      --query "Role.Arn" --output text 2>/dev/null || echo "")
    if [ -n "$ROLE_ARN" ] && [ "$ROLE_ARN" != "None" ]; then
      record_check "iam" "$ROLE" "pass" "$ROLE_ARN" "IAM: $ROLE exists"
    else
      record_check "iam" "$ROLE" "fail" "null" "IAM: $ROLE not found"
    fi
  done

  # Evidence bucket
  if aws_cli s3api head-bucket --bucket "$BUCKET_NAME" &>/dev/null; then
    record_check "storage" "$BUCKET_NAME" "pass" "s3://$BUCKET_NAME" "Bucket: $BUCKET_NAME exists"
  else
    record_check "storage" "$BUCKET_NAME" "fail" "null" "Bucket: $BUCKET_NAME not found"
  fi

  # Apply log
  if [ -n "$DEPLOYMENT_ID" ]; then
    if aws_cli s3api head-object --bucket "$BUCKET_NAME" --key "deploy-${DEPLOYMENT_ID}/terraform/apply.log" &>/dev/null; then
      record_check "storage" "apply-log" "pass" "s3://$BUCKET_NAME/deploy-${DEPLOYMENT_ID}/terraform/apply.log" "Bucket: apply.log uploaded"
    else
      record_check "storage" "apply-log" "fail" "null" "Bucket: apply.log not found at deploy-${DEPLOYMENT_ID}/terraform/"
    fi
  fi

  # CI/CD resources (Terraform-managed, destroyed on teardown)
  CICD_ARN=$(aws_cli iam get-role --role-name "jula-cicd-role" \
    --query "Role.Arn" --output text 2>/dev/null || echo "")
  if [ -n "$CICD_ARN" ] && [ "$CICD_ARN" != "None" ]; then
    record_check "iam" "jula-cicd-role" "pass" "$CICD_ARN" "IAM: jula-cicd-role exists"
  else
    record_check "iam" "jula-cicd-role" "fail" "null" "IAM: jula-cicd-role not found"
  fi

  OIDC_ARN=$(aws_cli iam list-open-id-connect-providers \
    --query "OpenIDConnectProviderList[0].Arn" --output text 2>/dev/null || echo "")
  if [ -n "$OIDC_ARN" ] && [ "$OIDC_ARN" != "None" ]; then
    record_check "iam" "oidc-provider" "pass" "$OIDC_ARN" "IAM: OIDC provider exists (GitHub Actions)"
  else
    record_check "iam" "oidc-provider" "fail" "null" "IAM: OIDC provider not found"
  fi

  # ---- Networking Checks ----
  echo ""
  echo "  🔗 Networking"

  # Private subnets
  SUBNET_COUNT=$(aws_cli ec2 describe-subnets \
    --filters "Name=tag:Name,Values=jula-private-*" \
    --query "length(Subnets)" --output text 2>/dev/null || echo "0")
  if [ "$SUBNET_COUNT" -ge 2 ]; then
    record_check "networking" "private-subnets" "pass" "$SUBNET_COUNT subnets" "Networking: $SUBNET_COUNT private subnets found"
  else
    record_check "networking" "private-subnets" "fail" "$SUBNET_COUNT subnets" "Networking: Expected 2 private subnets, found $SUBNET_COUNT"
  fi

  # NAT Gateway
  NAT_STATE=$(aws_cli ec2 describe-nat-gateways \
    --filter "Name=tag:Name,Values=jula-nat" \
    --query "NatGateways[?State!='deleted'] | [0].State" --output text 2>/dev/null || echo "missing")
  if [ "$NAT_STATE" == "available" ]; then
    record_check "networking" "nat-gateway" "pass" "$NAT_STATE" "Networking: NAT Gateway is available"
  else
    record_check "networking" "nat-gateway" "fail" "$NAT_STATE" "Networking: NAT Gateway not available ($NAT_STATE)"
  fi

  # Security Group
  SG_ID=$(aws_cli ec2 describe-security-groups \
    --filters "Name=tag:Name,Values=jula-vpc-endpoints-sg" \
    --query "SecurityGroups[0].GroupId" --output text 2>/dev/null || echo "missing")
  if [ -n "$SG_ID" ] && [ "$SG_ID" != "None" ] && [ "$SG_ID" != "missing" ]; then
    record_check "networking" "security-group" "pass" "$SG_ID" "Networking: Security group $SG_ID exists"
  else
    record_check "networking" "security-group" "fail" "null" "Networking: Jula security group not found"
  fi

  # VPC Endpoints — Infrastructure (Fargate needs these to function)
  echo ""
  echo "  🔒 VPC Endpoints (Infrastructure)"

  for SVC_NAME in ecr.api ecr.dkr logs secretsmanager sts; do
    EP_STATE=$(aws_cli ec2 describe-vpc-endpoints \
      --filters "Name=service-name,Values=com.amazonaws.${AWS_REGION}.${SVC_NAME}" "Name=tag:Name,Values=jula-*" \
      --query "VpcEndpoints[0].State" --output text 2>/dev/null || echo "missing")
    if [ "$EP_STATE" == "available" ]; then
      record_check "networking" "vpce-${SVC_NAME}" "pass" "$EP_STATE" "VPC Endpoint: ${SVC_NAME} is available"
    else
      record_check "networking" "vpce-${SVC_NAME}" "fail" "${EP_STATE}" "VPC Endpoint: ${SVC_NAME} not available (${EP_STATE})"
    fi
  done

  # S3 gateway endpoint
  S3_EP=$(aws_cli ec2 describe-vpc-endpoints \
    --filters "Name=service-name,Values=com.amazonaws.${AWS_REGION}.s3" "Name=vpc-endpoint-type,Values=Gateway" \
    --query "VpcEndpoints[0].State" --output text 2>/dev/null || echo "missing")
  if [ "$S3_EP" == "available" ]; then
    record_check "networking" "vpce-s3-gateway" "pass" "$S3_EP" "VPC Endpoint: S3 Gateway is available"
  else
    record_check "networking" "vpce-s3-gateway" "fail" "${S3_EP}" "VPC Endpoint: S3 Gateway not available (${S3_EP})"
  fi

  # VPC Endpoints — Audit Targets (collector calls these AWS APIs)
  echo ""
  echo "  🔒 VPC Endpoints (Audit Targets)"

  for SVC_NAME in ec2 cloudtrail kms rds; do
    EP_STATE=$(aws_cli ec2 describe-vpc-endpoints \
      --filters "Name=service-name,Values=com.amazonaws.${AWS_REGION}.${SVC_NAME}" "Name=tag:Name,Values=jula-*" \
      --query "VpcEndpoints[0].State" --output text 2>/dev/null || echo "missing")
    if [ "$EP_STATE" == "available" ]; then
      record_check "networking" "vpce-${SVC_NAME}" "pass" "$EP_STATE" "VPC Endpoint: ${SVC_NAME} is available"
    else
      record_check "networking" "vpce-${SVC_NAME}" "fail" "${EP_STATE}" "VPC Endpoint: ${SVC_NAME} not available (${EP_STATE})"
    fi
  done

  # ---- Security Checks ----
  echo ""
  echo "  🔒 Security"

  # S3 access logging
  LOG_TARGET=$(aws_cli s3api get-bucket-logging --bucket "$BUCKET_NAME" \
    --query "LoggingEnabled.TargetBucket" --output text 2>/dev/null || echo "")
  if [ -n "$LOG_TARGET" ] && [ "$LOG_TARGET" != "None" ]; then
    record_check "security" "s3-logging" "pass" "$LOG_TARGET" "Security: Evidence bucket access logging enabled"
  else
    record_check "security" "s3-logging" "fail" "null" "Security: Evidence bucket has no access logging"
  fi
}

# ============================================================================
# AWS TEARDOWN VERIFICATION
# ============================================================================
verify_teardown_aws() {
  # ECS cluster should be gone
  if aws_cli ecs describe-clusters --clusters jula-cluster --query "clusters[0].status" --output text &>/dev/null; then
    CLUSTER_STATUS=$(aws_cli ecs describe-clusters --clusters jula-cluster --query "clusters[0].status" --output text 2>/dev/null)
    if [ "$CLUSTER_STATUS" == "ACTIVE" ]; then
      record_check "compute" "jula-cluster" "fail" "jula-cluster" "ECS: jula-cluster still ACTIVE (should be destroyed)"
    else
      record_check "compute" "jula-cluster" "pass" "null" "ECS: jula-cluster destroyed"
    fi
  else
    record_check "compute" "jula-cluster" "pass" "null" "ECS: jula-cluster destroyed"
  fi

  # Task definitions should be deregistered (INACTIVE)
  # Note: AWS does not allow deletion of task definitions, only deregistration.
  for FAMILY in jula-collector jula-assessor; do
    TD_STATUS=$(aws_cli ecs describe-task-definition --task-definition "$FAMILY" \
      --query "taskDefinition.status" --output text 2>/dev/null || echo "MISSING")
    if [ "$TD_STATUS" == "INACTIVE" ] || [ "$TD_STATUS" == "MISSING" ] || [ "$TD_STATUS" == "None" ]; then
      record_check "compute" "$FAMILY" "pass" "null" "ECS: $FAMILY task definition deregistered"
    else
      record_check "compute" "$FAMILY" "fail" "$FAMILY" "ECS: $FAMILY task definition still ACTIVE (should be deregistered)"
    fi
  done

  # ECR repositories should be gone
  for REPO in jula-collector jula-assessor; do
    if aws_cli ecr describe-repositories --repository-names "$REPO" &>/dev/null; then
      record_check "registry" "$REPO" "fail" "$REPO" "ECR: $REPO still exists (should be destroyed)"
    else
      record_check "registry" "$REPO" "pass" "null" "ECR: $REPO destroyed"
    fi
  done

  # Secrets should be gone
  for SECRET in jula-signing-key jula-public-key jula-source-token jula-dispatch-token; do
    if aws_cli secretsmanager describe-secret --secret-id "$SECRET" &>/dev/null; then
      record_check "secret" "$SECRET" "fail" "$SECRET" "Secret: $SECRET still exists (should be destroyed)"
    else
      record_check "secret" "$SECRET" "pass" "null" "Secret: $SECRET destroyed"
    fi
  done

  # Scheduler schedules should be gone
  for SCHEDULE in jula-daily-evidence-collection jula-daily-evidence-assessment; do
    if aws_cli scheduler get-schedule --name "$SCHEDULE" &>/dev/null; then
      record_check "scheduler" "$SCHEDULE" "fail" "$SCHEDULE" "Scheduler: $SCHEDULE still exists (should be destroyed)"
    else
      record_check "scheduler" "$SCHEDULE" "pass" "null" "Scheduler: $SCHEDULE destroyed"
    fi
  done

  # IAM runtime roles should be gone
  for ROLE in jula-ecs-execution-role jula-ecs-task-role jula-scheduler-role; do
    if aws_cli iam get-role --role-name "$ROLE" &>/dev/null; then
      ROLE_ARN=$(aws_cli iam get-role --role-name "$ROLE" --query "Role.Arn" --output text 2>/dev/null)
      record_check "iam" "$ROLE" "fail" "$ROLE_ARN" "IAM: $ROLE still exists (should be destroyed)"
    else
      record_check "iam" "$ROLE" "pass" "null" "IAM: $ROLE destroyed"
    fi
  done

  # CI/CD resources (Terraform-managed, should be destroyed)
  if aws_cli iam get-role --role-name "jula-cicd-role" &>/dev/null; then
    CICD_ARN=$(aws_cli iam get-role --role-name "jula-cicd-role" --query "Role.Arn" --output text 2>/dev/null)
    record_check "iam" "jula-cicd-role" "fail" "$CICD_ARN" "IAM: jula-cicd-role still exists (should be destroyed)"
  else
    record_check "iam" "jula-cicd-role" "pass" "null" "IAM: jula-cicd-role destroyed"
  fi

  OIDC_ARN=$(aws_cli iam list-open-id-connect-providers \
    --query "OpenIDConnectProviderList[0].Arn" --output text 2>/dev/null || echo "")
  if [ -n "$OIDC_ARN" ] && [ "$OIDC_ARN" != "None" ]; then
    record_check "iam" "oidc-provider" "fail" "$OIDC_ARN" "IAM: OIDC provider still exists (should be destroyed)"
  else
    record_check "iam" "oidc-provider" "pass" "null" "IAM: OIDC provider destroyed"
  fi

  # Evidence bucket should survive
  if aws_cli s3api head-bucket --bucket "$BUCKET_NAME" &>/dev/null; then
    record_check "storage" "$BUCKET_NAME" "pass" "s3://$BUCKET_NAME" "Bucket: $BUCKET_NAME survived"
  else
    record_check "storage" "$BUCKET_NAME" "fail" "null" "Bucket: $BUCKET_NAME missing (should be permanent)"
  fi

  # Terraform ops artifacts should exist in bucket
  ARCHIVE_COUNT=$(aws_cli s3 ls "s3://$BUCKET_NAME/deploy-" --recursive 2>/dev/null | grep '/terraform/' | wc -l | tr -d ' ' || echo "0")
  if [ "$ARCHIVE_COUNT" -gt 0 ]; then
    record_check "storage" "terraform-ops" "pass" "s3://$BUCKET_NAME/deploy-*/terraform/" "Archive: $ARCHIVE_COUNT ops files preserved"
  else
    record_check "storage" "terraform-ops" "fail" "null" "Archive: terraform/ ops folder is empty or missing"
  fi
}

# --- Execute the appropriate verification ---
if [ "$ENV" == "gcp" ]; then
  if [ "$MODE" == "standup" ]; then
    verify_standup_gcp
  else
    verify_teardown_gcp
  fi
elif [ "$ENV" == "aws" ]; then
  if [ "$MODE" == "standup" ]; then
    verify_standup_aws
  else
    verify_teardown_aws
  fi
fi

# --- Summary ---
TOTAL=$((PASS + FAIL))
echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "[RESULT] $PASS/$TOTAL checks passed ✅"
else
  echo "[RESULT] $PASS/$TOTAL checks passed, $FAIL failed ❌"
fi

# --- Write JSON report ---
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
DEPLOYMENT_ID_JSON=${DEPLOYMENT_ID:-null}
if [ "$DEPLOYMENT_ID_JSON" != "null" ]; then
  DEPLOYMENT_ID_JSON="\"$DEPLOYMENT_ID_JSON\""
fi

# Determine the deployment ID for file placement.
# In standup mode, it's available from state. In teardown mode, find it
# from the most recent ops directory that isn't _unknown.
UPLOAD_DEPLOYMENT_ID="$DEPLOYMENT_ID"
if [ -z "$UPLOAD_DEPLOYMENT_ID" ]; then
  for D in $(ls -td deploy/terraform/$ENV/ops/*/ 2>/dev/null); do
    DIR_NAME=$(basename "$D")
    if [ "$DIR_NAME" != "_unknown" ]; then
      UPLOAD_DEPLOYMENT_ID="$DIR_NAME"
      break
    fi
  done
fi

VERIFY_FILENAME="verify_${MODE}.json"
if [ -n "$UPLOAD_DEPLOYMENT_ID" ]; then
  OPS_DIR=$(ops_dir "$UPLOAD_DEPLOYMENT_ID")
else
  OPS_DIR="deploy/terraform/$ENV/ops/_unknown"
  mkdir -p "$OPS_DIR"
fi
VERIFY_FILE="$OPS_DIR/$VERIFY_FILENAME"

cat > "$VERIFY_FILE" <<EOF
{
  "timestamp": "$TIMESTAMP",
  "environment": "$ENV",
  "mode": "$MODE",
  "deployment_id": $DEPLOYMENT_ID_JSON,
  "summary": {
    "total": $TOTAL,
    "pass": $PASS,
    "fail": $FAIL
  },
  "checks": [$CHECKS_JSON]
}
EOF

echo ""
echo "[REPORT] Written to $VERIFY_FILE"

# --- Upload verify report to evidence bucket ---
if [ -n "$UPLOAD_DEPLOYMENT_ID" ]; then
  PREFIX=$(bucket_prefix "$UPLOAD_DEPLOYMENT_ID")
  if upload_to_bucket "$VERIFY_FILE" "$PREFIX/terraform/$VERIFY_FILENAME"; then
    echo "[UPLOAD] Uploaded to $PREFIX/terraform/$VERIFY_FILENAME"
  else
    echo "[UPLOAD] Failed to upload $VERIFY_FILENAME"
  fi
else
  echo "[UPLOAD] Skipped (no deployment ID found)"
fi

exit "$FAIL"
