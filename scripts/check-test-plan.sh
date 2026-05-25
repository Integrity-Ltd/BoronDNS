#!/usr/bin/env bash
set -euo pipefail

test_plan="docs/test-plan.md"

if [[ ! -f "$test_plan" ]]; then
  printf 'missing Test Plan: %s\n' "$test_plan" >&2
  exit 66
fi

require_text() {
  local needle="$1"
  if ! grep -F "$needle" "$test_plan" >/dev/null 2>&1; then
    printf 'Test Plan missing required text: %s\n' "$needle" >&2
    exit 1
  fi
}

for heading in \
  "## Cadence Classes" \
  "## Method Cadence Map" \
  "## Continuous Execution" \
  "## Periodic Execution" \
  "## Gate Execution" \
  "## Regression Policy" \
  "## Release Notes Inputs"; do
  require_text "$heading"
done

for method in \
  "Static analysis" \
  "Unit test" \
  "Property-based test" \
  "Integration test" \
  "Conformance test" \
  "Fuzz test" \
  "Performance test" \
  "Differential test" \
  "Interoperability test" \
  "Soak test" \
  "Operational test" \
  "Security audit" \
  "External operator acceptance"; do
  require_text "$method"
done

for cadence in Continuous Periodic Gate; do
  require_text "$cadence"
done

require_text "regression.performance_threshold_pct"
require_text "defaults to **10**"
require_text "median of the last five"
require_text "release measurements"
require_text "A release with an untriaged"
require_text "regression must not proceed"
require_text "scripts/check.sh"
require_text "scripts/release-evidence-snapshot.sh"
require_text "scripts/check-unsafe-boundaries.py"
require_text "scripts/capture-unsafe-dependency-evidence.sh"
require_text "campaign-summary.tsv"
require_text "scripts/capture-info-verbosity-handoff.sh"
require_text "scripts/capture-benchmark-handoff.sh"
require_text "scripts/capture-soak-handoff.sh"
require_text "scripts/capture-release-handoff.sh"

printf 'Test Plan check passed: %s\n' "$test_plan"
