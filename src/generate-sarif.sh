#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# SARIF Report Generator
# Converts Penetrify scan results (JSON) to SARIF format for GitHub Security.
#
# SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
# GitHub SARIF: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
# =============================================================================

RESULTS_DIR=""
OUTPUT=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --results-dir) RESULTS_DIR="$2"; shift 2 ;;
    --output)      OUTPUT="$2"; shift 2 ;;
    *)             echo "Unknown option: $1"; exit 1 ;;
  esac
done

RESULTS_FILE="$RESULTS_DIR/results.json"

if [[ ! -f "$RESULTS_FILE" ]]; then
  echo "::error::Results file not found: $RESULTS_FILE"
  exit 1
fi

# Map Penetrify severity → SARIF level
# SARIF only supports: error, warning, note, none
severity_to_sarif_level() {
  case "$1" in
    critical|high) echo "error" ;;
    medium)        echo "warning" ;;
    low|info)      echo "note" ;;
    *)             echo "warning" ;;
  esac
}

# Map Penetrify severity → SARIF security-severity score
severity_to_score() {
  case "$1" in
    critical) echo "9.5" ;;
    high)     echo "8.0" ;;
    medium)   echo "5.5" ;;
    low)      echo "3.0" ;;
    info)     echo "1.0" ;;
    *)        echo "5.0" ;;
  esac
}

# Build SARIF using jq
# Results file structure: {"success": true, "data": {"vulnerabilities": [...]}}
jq -n \
  --slurpfile results "$RESULTS_FILE" \
  '
($results[0].data.vulnerabilities // []) as $vulns |
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Penetrify",
          "organization": "Algofy s.r.o.",
          "semanticVersion": "1.0.0",
          "informationUri": "https://penetrify.cloud",
          "rules": [
            $vulns
            | unique_by(.category // .vulnerability_id)
            | .[]
            | {
                "id": (.cwe_id // .category // .vulnerability_id),
                "name": .title,
                "shortDescription": { "text": .title },
                "fullDescription": { "text": (.description // .title) },
                "helpUri": (.references[0] // null),
                "properties": {
                  "security-severity": (
                    if .severity == "critical" then "9.5"
                    elif .severity == "high" then "8.0"
                    elif .severity == "medium" then "5.5"
                    elif .severity == "low" then "3.0"
                    else "1.0"
                    end
                  ),
                  "tags": ["security", "penetration-test", (.category // "other")]
                }
              }
          ]
        }
      },
      "results": [
        $vulns[] |
        {
          "ruleId": (.cwe_id // .category // .vulnerability_id),
          "level": (
            if .severity == "critical" or .severity == "high" then "error"
            elif .severity == "medium" then "warning"
            else "note"
            end
          ),
          "message": {
            "text": .description,
            "markdown": (
              "**" + .title + "**\n\n" +
              .description + "\n\n" +
              "**Severity:** " + .severity + "\n" +
              "**Affected URL:** " + (.affected_url // "N/A") + "\n\n" +
              if .recommendation then "**Remediation:** " + .recommendation else "" end
            )
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": (.affected_url // "unknown"),
                  "uriBaseId": "%SRCROOT%"
                }
              }
            }
          ],
          "fingerprints": {
            "penetrify/finding/v1": .vulnerability_id
          }
        }
      ]
    }
  ]
}' > "$OUTPUT"

FINDINGS_COUNT=$(jq '.runs[0].results | length' "$OUTPUT")
echo "SARIF report generated: $OUTPUT ($FINDINGS_COUNT findings)"
echo "sarif-file=$OUTPUT" >> "$GITHUB_OUTPUT"
