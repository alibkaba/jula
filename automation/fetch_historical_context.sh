#!/usr/bin/env bash
# ============================================================================
# fetch_historical_context.sh — Extract previous valid payloads
# ============================================================================
# Purpose: Fetches stored artifacts from the previous 1 to 5 days using git
#          object lineage or GCS paths, filtering out secrets and writing
#          with 0600/0700 disk permission flags to prevent access leakage.
# ============================================================================

set -euo pipefail

SCRATCH_DIR="${1:-}"
DAYS_LOOKBACK="${2:-5}"

if [ -z "$SCRATCH_DIR" ]; then
  echo "Error: scratch directory argument is required" >&2
  exit 1
fi

# Ensure directory is created with 0700 permissions
mkdir -p "$SCRATCH_DIR"
chmod 0700 "$SCRATCH_DIR"

echo "📂 Fetching historical context into $SCRATCH_DIR (looking back up to $DAYS_LOOKBACK days/commits)..."

# Step 1: Extract preceding valid payloads from Git history
FIXTURE_PATHS=(
  "tests/e2e/fixtures/mock_api.yaml"
  "../jula-compliance-as-code/policies/normalization/gcp/fixtures/sample_api_response.json"
)

# Loop through the git log commits to extract past versions
for ref in $(git log -n "$DAYS_LOOKBACK" --format="%H"); do
  for path in "${FIXTURE_PATHS[@]}"; do
    if git show "${ref}:${path}" >/dev/null 2>&1; then
      filename=$(basename "$path")
      out_name="git_${ref:0:8}_${filename}"
      out_path="${SCRATCH_DIR}/${out_name}"
      
      # Extract version from git
      git show "${ref}:${path}" > "$out_path"
      
      # Apply information exposure mitigation (strip headers/auth keys)
      if [[ "$filename" == *.json ]]; then
        if command -v jq >/dev/null 2>&1; then
          jq 'walk(if type == "object" then del(.Authorization, .authorization, .token, .access_token, .jwt, .secret, .headers) else . end)' "$out_path" > "${out_path}.tmp" && mv "${out_path}.tmp" "$out_path"
        fi
      fi
      
      # Enforce 0600 file permissions
      chmod 0600 "$out_path"
      echo "  - Extracted git historical context: $out_name"
    fi
  done
done

# Step 2: Extract preceding valid payloads from Google Cloud Storage if available
if command -v gcloud >/dev/null 2>&1; then
  echo "☁️ GCP SDK detected. Attempting to list gs://jula-evidence-ledger..."
  for i in $(seq 1 "$DAYS_LOOKBACK"); do
    if date -v -1d >/dev/null 2>&1; then
      TARGET_DATE=$(date -v "-${i}d" "+%Y-%m-%d")
    else
      TARGET_DATE=$(date -d "${i} days ago" "+%Y-%m-%d")
    fi
    
    GCS_PATH="gs://jula-evidence-ledger/${TARGET_DATE}/evidence/"
    
    if gcloud storage ls "$GCS_PATH" >/dev/null 2>&1; then
      TMP_DOWNLOAD_DIR="${SCRATCH_DIR}/gcs_${TARGET_DATE}"
      mkdir -p "$TMP_DOWNLOAD_DIR"
      chmod 0700 "$TMP_DOWNLOAD_DIR"
      
      if gcloud storage cp -r "${GCS_PATH}*.json" "$TMP_DOWNLOAD_DIR" >/dev/null 2>&1; then
        for f in "$TMP_DOWNLOAD_DIR"/*.json; do
          if [ -f "$f" ]; then
            # Clean/strip sensitive fields
            if command -v jq >/dev/null 2>&1; then
              jq 'walk(if type == "object" then del(.Authorization, .authorization, .token, .access_token, .jwt, .secret, .headers) else . end)' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
            fi
            chmod 0600 "$f"
            mv "$f" "${SCRATCH_DIR}/gcs_${TARGET_DATE}_$(basename "$f")"
          fi
        done
      fi
      rm -rf "$TMP_DOWNLOAD_DIR"
    fi
  done
else
  echo "⚠️ Cloud storage lookup skipped (gcloud CLI not installed)."
fi

echo "✅ Historical context collection complete. Files written with 0600 permissions."
