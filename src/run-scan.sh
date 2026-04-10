#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Penetrify Scan Runner
# Triggers a test via the Penetrify API and optionally waits for results.
# =============================================================================

# --- Parse Arguments ---
APPLICATION_ID=""
TARGET=""
SCAN_TYPE="automatic"
SEVERITY_THRESHOLD="high"
WAIT="true"
TIMEOUT=1800
OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --application-id)     APPLICATION_ID="$2"; shift 2 ;;
    --target)             TARGET="$2"; shift 2 ;;
    --scan-type)          SCAN_TYPE="$2"; shift 2 ;;
    --severity-threshold) SEVERITY_THRESHOLD="$2"; shift 2 ;;
    --wait)               WAIT="$2"; shift 2 ;;
    --timeout)            TIMEOUT="$2"; shift 2 ;;
    --output-dir)         OUTPUT_DIR="$2"; shift 2 ;;
    *)                    echo "Unknown option: $1"; exit 1 ;;
  esac
done

# --- Validate ---
if [[ -z "$APPLICATION_ID" ]]; then
  echo "::error::application-id is required"
  exit 1
fi

if [[ -z "${PENETRIFY_API_KEY:-}" ]]; then
  echo "::error::PENETRIFY_API_KEY is not set. Add it as a GitHub Secret."
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

API_BASE="https://api.penetrify.cloud/api/v1"

# Helper: curl with auth
penetrify_curl() {
  curl -s -H "X-API-Key: $PENETRIFY_API_KEY" -H "Content-Type: application/json" "$@"
}

penetrify_curl_with_code() {
  curl -s -w "\n%{http_code}" -H "X-API-Key: $PENETRIFY_API_KEY" -H "Content-Type: application/json" "$@"
}

# --- Create Test ---
echo "::group::Creating Penetrify test"
echo "Application: $APPLICATION_ID"
echo "Scan mode: $SCAN_TYPE"
[[ -n "$TARGET" ]] && echo "Target: $TARGET"

# Build payload safely with jq to avoid shell injection
PAYLOAD=$(jq -n \
  --arg name "CI/CD Security Scan ($(date -u '+%Y-%m-%d %H:%M UTC'))" \
  --arg scan_mode "$SCAN_TYPE" \
  --arg target "$TARGET" \
  '{
    name: $name,
    scan_mode: $scan_mode,
    target_urls: (if $target != "" then [$target] else [] end)
  }')

CREATE_RESPONSE=$(penetrify_curl_with_code \
  -X POST "$API_BASE/applications/$APPLICATION_ID/tests" \
  -d "$PAYLOAD")

HTTP_CODE=$(echo "$CREATE_RESPONSE" | tail -1)
BODY=$(echo "$CREATE_RESPONSE" | head -n -1)

if [[ "$HTTP_CODE" != "201" && "$HTTP_CODE" != "200" ]]; then
  echo "::error::Failed to create test (HTTP $HTTP_CODE): $BODY"
  exit 1
fi

TEST_ID=$(echo "$BODY" | jq -r '.data.test_id')
if [[ -z "$TEST_ID" || "$TEST_ID" == "null" ]]; then
  echo "::error::Could not parse test_id from response: $BODY"
  exit 1
fi

echo "Test created: $TEST_ID"
echo "test-id=$TEST_ID" >> "$GITHUB_OUTPUT"

# --- Start Test ---
START_RESPONSE=$(penetrify_curl_with_code \
  -X POST "$API_BASE/applications/$APPLICATION_ID/tests/$TEST_ID/start")

HTTP_CODE=$(echo "$START_RESPONSE" | tail -1)
BODY=$(echo "$START_RESPONSE" | head -n -1)

if [[ "$HTTP_CODE" != "200" ]]; then
  echo "::error::Failed to start test (HTTP $HTTP_CODE): $BODY"
  exit 1
fi

echo "Test queued successfully"
echo "::endgroup::"

# --- Wait for Results (if enabled) ---
if [[ "$WAIT" == "true" ]]; then
  echo "::group::Waiting for scan results (timeout: ${TIMEOUT}s)"

  START_TIME=$(date +%s)
  STATUS="pending"

  while [[ "$STATUS" == "pending" || "$STATUS" == "queued" || "$STATUS" == "running" ]]; do
    ELAPSED=$(( $(date +%s) - START_TIME ))
    if [[ $ELAPSED -ge $TIMEOUT ]]; then
      echo "::warning::Scan timed out after ${TIMEOUT}s"
      echo "status=timeout" >> "$GITHUB_OUTPUT"
      exit 1
    fi

    sleep 15

    POLL_RESPONSE=$(penetrify_curl \
      "$API_BASE/applications/$APPLICATION_ID/tests/$TEST_ID/status")

    STATUS=$(echo "$POLL_RESPONSE" | jq -r '.data.status // "unknown"')
    PROGRESS=$(echo "$POLL_RESPONSE" | jq -r '.data.progress_percentage // "N/A"')
    echo "Status: $STATUS | Progress: ${PROGRESS}% | Elapsed: ${ELAPSED}s"
  done

  echo "::endgroup::"

  if [[ "$STATUS" != "completed" ]]; then
    echo "::error::Scan ended with status: $STATUS"
    echo "status=$STATUS" >> "$GITHUB_OUTPUT"
    exit 1
  fi

  echo "status=completed" >> "$GITHUB_OUTPUT"

  # --- Fetch Vulnerabilities ---
  echo "::group::Fetching scan results"

  RESULTS=$(penetrify_curl \
    "$API_BASE/applications/$APPLICATION_ID/tests/$TEST_ID/vulnerabilities")

  echo "$RESULTS" > "$OUTPUT_DIR/results.json"

  # Parse counts from vulnerability list
  VULNS=$(echo "$RESULTS" | jq '.data.vulnerabilities')
  TOTAL=$(echo "$VULNS" | jq 'length')
  CRITICAL=$(echo "$VULNS" | jq '[.[] | select(.severity == "critical")] | length')
  HIGH=$(echo "$VULNS" | jq '[.[] | select(.severity == "high")] | length')
  MEDIUM=$(echo "$VULNS" | jq '[.[] | select(.severity == "medium")] | length')
  LOW=$(echo "$VULNS" | jq '[.[] | select(.severity == "low")] | length')

  echo "findings-count=$TOTAL" >> "$GITHUB_OUTPUT"
  echo "critical-count=$CRITICAL" >> "$GITHUB_OUTPUT"
  echo "high-count=$HIGH" >> "$GITHUB_OUTPUT"

  REPORT_URL="https://app.penetrify.cloud/tests/$TEST_ID"
  echo "report-url=$REPORT_URL" >> "$GITHUB_OUTPUT"

  echo ""
  echo "╔══════════════════════════════════════╗"
  echo "║       Penetrify Scan Summary         ║"
  echo "╠══════════════════════════════════════╣"
  printf "║  Critical: %-4s  High: %-4s         ║\n" "$CRITICAL" "$HIGH"
  printf "║  Medium:   %-4s  Low:  %-4s         ║\n" "$MEDIUM" "$LOW"
  printf "║  Total findings: %-4s               ║\n" "$TOTAL"
  echo "╠══════════════════════════════════════╣"
  printf "║  Report: %-30s  ║\n" "$REPORT_URL"
  echo "╚══════════════════════════════════════╝"
  echo ""

  echo "::endgroup::"

  # --- Evaluate Threshold ---
  SEVERITY_MAP='{"critical":4,"high":3,"medium":2,"low":1,"info":0}'
  THRESHOLD_VALUE=$(echo "$SEVERITY_MAP" | jq -r ".\"$SEVERITY_THRESHOLD\"")

  FAIL=false
  if [[ $THRESHOLD_VALUE -le 4 && $CRITICAL -gt 0 ]]; then FAIL=true; fi
  if [[ $THRESHOLD_VALUE -le 3 && $HIGH -gt 0 ]]; then FAIL=true; fi
  if [[ $THRESHOLD_VALUE -le 2 && $MEDIUM -gt 0 ]]; then FAIL=true; fi
  if [[ $THRESHOLD_VALUE -le 1 && $LOW -gt 0 ]]; then FAIL=true; fi

  if [[ "$FAIL" == "true" ]]; then
    echo "::error::Scan found vulnerabilities at or above '$SEVERITY_THRESHOLD' severity. See report: $REPORT_URL"
    exit 1
  fi

  echo "✅ No findings at or above '$SEVERITY_THRESHOLD' severity."

else
  echo "status=triggered" >> "$GITHUB_OUTPUT"
  echo "Scan triggered in async mode. Check results at: https://app.penetrify.cloud/tests/$TEST_ID"
fi
