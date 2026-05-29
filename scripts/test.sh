#!/bin/bash
# ============================================================================
# test.sh — Dockerized Go Test Runner
# ============================================================================
# Purpose: Runs the Jula Evidence Collector test suite in a containerized
#          Go environment (1.25) to ensure CI parity.
#
# Usage:   ./scripts/test.sh
# ============================================================================

set -euo pipefail

# --- Configuration ---
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# --- Execution ---
echo "🧪 Running Jula Test Suite via Docker..."

docker run --rm \
  -v "${REPO_ROOT}:/workspace" \
  -w /workspace \
  golang:1.25 \
  sh -c "go test -v -coverprofile=coverage.out ./collector/... ./core/... ./evaluator/... && go tool cover -func=coverage.out"

# --- Post-run ---
if [ -f "${REPO_ROOT}/coverage.out" ]; then
  echo "📊 Coverage report generated: coverage.out"
fi

echo "✅ Test suite execution complete."
