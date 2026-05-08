#!/usr/bin/env bash
# fetch_aikido.sh - Pull open issues from Aikido Security and generate
# a Jula BYOE vulnerability scan evidence file.
#
# Usage:
#   export AIKIDO_API_KEY="your-api-key-here"
#   ./integrations/fetch_aikido.sh
#
# Output:
#   evidence-output/byoe_vulnerability_scan.json

set -euo pipefail

# ── Validate Dependencies ────────────────────────────────────
for cmd in curl jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' is required but not installed." >&2
    exit 1
  fi
done

# ── Validate Environment ─────────────────────────────────────
if [[ -z "${AIKIDO_API_KEY:-}" ]]; then
  echo "ERROR: AIKIDO_API_KEY environment variable is not set." >&2
  echo "  export AIKIDO_API_KEY=\"your-api-key\"" >&2
  exit 1
fi

# ── Configuration ────────────────────────────────────────────
AIKIDO_API_URL="https://app.aikido.dev/api/public/v1/issues/export?format=json&filter_status=open"
OUTPUT_DIR="evidence-output"
OUTPUT_FILE="${OUTPUT_DIR}/byoe_vulnerability_scan.json"

mkdir -p "$OUTPUT_DIR"

# ── Fetch Issues from Aikido ─────────────────────────────────
echo "Fetching open issues from Aikido Security..."

RAW_RESPONSE=$(curl -sSf \
  -H "Authorization: Bearer ${AIKIDO_API_KEY}" \
  -H "Accept: application/json" \
  "$AIKIDO_API_URL")

# ── Count Severities ─────────────────────────────────────────
# Aikido issues contain a "severity" field. We count each level.
CRITICAL=$(echo "$RAW_RESPONSE" | jq '[.[] | select(.severity == "critical")] | length')
HIGH=$(echo "$RAW_RESPONSE" | jq '[.[] | select(.severity == "high")] | length')
MEDIUM=$(echo "$RAW_RESPONSE" | jq '[.[] | select(.severity == "medium")] | length')
LOW=$(echo "$RAW_RESPONSE" | jq '[.[] | select(.severity == "low")] | length')

# ── Generate BYOE Evidence File ──────────────────────────────
SCAN_ID="aikido-$(date -u +%Y%m%dT%H%M%SZ)"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
  --arg scan_id "$SCAN_ID" \
  --arg timestamp "$TIMESTAMP" \
  --arg scanner_name "Aikido Security" \
  --arg target "alibkaba/jula-evidence-collector" \
  --argjson critical "$CRITICAL" \
  --argjson high "$HIGH" \
  --argjson medium "$MEDIUM" \
  --argjson low "$LOW" \
  --arg raw_url "https://app.aikido.dev" \
  '{
    scan_id: $scan_id,
    timestamp: $timestamp,
    scanner_name: $scanner_name,
    target: $target,
    findings_summary: {
      critical: $critical,
      high: $high,
      medium: $medium,
      low: $low
    },
    raw_report_url: $raw_url
  }' > "$OUTPUT_FILE"

echo "Evidence written to ${OUTPUT_FILE}"
echo "  Critical: ${CRITICAL} | High: ${HIGH} | Medium: ${MEDIUM} | Low: ${LOW}"
