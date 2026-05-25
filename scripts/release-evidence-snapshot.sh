#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/evidence-artifacts.sh"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_root="${OXIDEDNS_EVIDENCE_DIR:-$repo_root/target/evidence}"
snapshot_dir="$evidence_root/$timestamp"
mkdir -p "$snapshot_dir/logs" "$snapshot_dir/interop-primary-versions"
printf 'source_path\tsnapshot_path\n' >"$snapshot_dir/interop-primary-versions/INDEX.tsv"

for candidate in "${CARGO_HOME:-$HOME/.cargo}/bin" /cache/cargo/bin; do
  if [[ -d "$candidate" ]]; then
    PATH="$candidate:$PATH"
  fi
done
export PATH

run_and_capture() {
  local name="$1"
  shift
  local log="$snapshot_dir/logs/$name.log"
  local before="$snapshot_dir/logs/$name.primary-version.before"
  list_primary_version_artifacts "$repo_root" >"$before"

  set +e
  {
    printf '$'
    printf ' %q' "$@"
    printf '\n\n'
    "$@"
  } >"$log" 2>&1
  local status=$?
  set -e

  capture_new_primary_version_artifacts "$repo_root" "$snapshot_dir" "$name" "$before"
  rm -f "$before"
  return "$status"
}

record_version() {
  local name="$1"
  shift
  local log="$snapshot_dir/logs/tool-versions.log"
  {
    printf '$'
    printf ' %q' "$@"
    printf '\n'
    if command -v "$1" >/dev/null 2>&1; then
      "$@" 2>&1 || true
    else
      printf 'missing: %s\n' "$1"
    fi
    printf '\n'
  } >>"$log"
}

require_positive_integer() {
  local name="$1"
  local value="$2"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || {
    printf '%s must be a positive integer: %s\n' "$name" "$value" >&2
    exit 1
  }
}

run_rrl_campaign() {
  local name="$1"
  local campaign_dir="$snapshot_dir/$name"
  local iterations="${OXIDEDNS_EVIDENCE_RRL_CAMPAIGN_ITERATIONS:-3}"
  local duration="${OXIDEDNS_EVIDENCE_RRL_CAMPAIGN_DURATION:-}"

  if [[ -n "$duration" ]]; then
    require_positive_integer OXIDEDNS_EVIDENCE_RRL_CAMPAIGN_DURATION "$duration"
    run_and_capture "$name" bash -lc \
      "cd '$repo_root' && scripts/rrl-evidence-campaign.sh --duration '$duration' --evidence-dir '$campaign_dir'"
  else
    require_positive_integer OXIDEDNS_EVIDENCE_RRL_CAMPAIGN_ITERATIONS "$iterations"
    run_and_capture "$name" bash -lc \
      "cd '$repo_root' && scripts/rrl-evidence-campaign.sh --iterations '$iterations' --evidence-dir '$campaign_dir'"
  fi
}

cat >"$snapshot_dir/README.md" <<EOF
# OxideDNS Release Evidence Snapshot

- Created UTC: $timestamp
- Repository: $repo_root
- Commit: $(git -C "$repo_root" rev-parse HEAD)
- Branch: $(git -C "$repo_root" branch --show-current)

This directory contains command logs captured for release review, including
safe-Rust, maintainability, source requirement-reference,
interface-compatibility, canonical log-field, and lazy log-formatting audit
output, plus retained unsafe dependency enumeration.
It is an evidence collection artifact, not a substitute for the SRS
traceability matrix, 24-hour fuzzing campaigns, completed soak testing, or
production benchmark reports. The default `info-verbosity-handoff/`,
`interface-compatibility/`, `benchmark-handoff/`, `soak-handoff/`,
`reproducible-build-handoff/`, and `release-handoff/` artifacts are
release/operations setup scaffolds for later production-depth info-verbosity
profile, release-to-release interface diff review, Reference Hardware/Profile
benchmark, long-duration soak, independent reproducible-build comparison,
scheduled-CI, signing, release-note, and external-operator execution; they are
not completed profile, compatibility-diff, benchmark, soak, reproducible-build,
or release-acceptance results.

Successful real-primary interop runs copy their primary-version artifacts to
interop-primary-versions/ with an INDEX.tsv mapping source and snapshot paths.
EOF

git -C "$repo_root" status --short >"$snapshot_dir/git-status.txt"
git -C "$repo_root" log --oneline -20 >"$snapshot_dir/git-log.txt"
git -C "$repo_root" diff --stat >"$snapshot_dir/git-diff-stat.txt"
git -C "$repo_root" diff --check >"$snapshot_dir/git-diff-check.txt"

: >"$snapshot_dir/logs/tool-versions.log"
record_version rustc rustc --version
record_version cargo cargo --version
record_version cargo-deny cargo deny --version
record_version cargo-fuzz cargo fuzz --version
record_version cargo-bloat cargo bloat --version
record_version cargo-machete cargo machete --version
record_version cargo-geiger cargo geiger --version
record_version cargo-llvm-cov cargo llvm-cov --version
record_version docker docker --version
record_version dig dig -v
record_version curl curl --version
record_version python3 python3 --version

{
  printf '# OxideDNS Verification Commands\n\n'
  awk '/^```sh$/ { in_block=1 } in_block { print } /^```$/ && in_block { in_block=0 }' \
    "$repo_root/docs/mvp-gap-register.md"
} >"$snapshot_dir/verification-commands.md"

run_and_capture test-plan-check bash -lc "cd '$repo_root' && scripts/check-test-plan.sh"
run_and_capture security-policy-check bash -lc "cd '$repo_root' && scripts/check-security-policy.sh"
run_and_capture cli-evidence bash -lc "cd '$repo_root' && OXIDEDNS_CLI_EVIDENCE_DIR='$snapshot_dir/cli-evidence' scripts/capture-cli-evidence.sh"
run_and_capture log-evidence bash -lc "cd '$repo_root' && OXIDEDNS_LOG_EVIDENCE_DIR='$snapshot_dir/log-evidence' scripts/capture-log-evidence.sh"
run_and_capture signal-evidence bash -lc "cd '$repo_root' && OXIDEDNS_SIGNAL_EVIDENCE_DIR='$snapshot_dir/signal-evidence' scripts/capture-signal-evidence.sh"
run_and_capture health-metrics-evidence bash -lc "cd '$repo_root' && OXIDEDNS_HEALTH_METRICS_EVIDENCE_DIR='$snapshot_dir/health-metrics-evidence' scripts/capture-health-metrics-evidence.sh"
run_and_capture malformed-query-evidence bash -lc "cd '$repo_root' && OXIDEDNS_MALFORMED_QUERY_EVIDENCE_DIR='$snapshot_dir/malformed-query-evidence' scripts/capture-malformed-query-evidence.sh"
run_and_capture portability-evidence bash -lc "cd '$repo_root' && OXIDEDNS_PORTABILITY_EVIDENCE_DIR='$snapshot_dir/portability-evidence' scripts/capture-portability-evidence.sh"
run_and_capture resource-evidence bash -lc "cd '$repo_root' && OXIDEDNS_RESOURCE_EVIDENCE_DIR='$snapshot_dir/resource-evidence' scripts/capture-resource-evidence.sh"
run_and_capture coverage-evidence bash -lc "cd '$repo_root' && OXIDEDNS_COVERAGE_EVIDENCE_DIR='$snapshot_dir/coverage-evidence' scripts/capture-coverage-evidence.sh"
run_and_capture unsafe-dependency-evidence bash -lc "cd '$repo_root' && OXIDEDNS_UNSAFE_DEPENDENCY_EVIDENCE_DIR='$snapshot_dir/unsafe-dependency-evidence' scripts/capture-unsafe-dependency-evidence.sh"
run_and_capture interface-compatibility bash -lc "cd '$repo_root' && OXIDEDNS_INTERFACE_COMPATIBILITY_DIR='$snapshot_dir/interface-compatibility' scripts/capture-interface-compatibility-evidence.sh"
run_and_capture info-verbosity-handoff bash -lc "cd '$repo_root' && OXIDEDNS_INFO_VERBOSITY_HANDOFF_DIR='$snapshot_dir/info-verbosity-handoff' scripts/capture-info-verbosity-handoff.sh"
run_and_capture benchmark-handoff bash -lc "cd '$repo_root' && OXIDEDNS_BENCHMARK_HANDOFF_DIR='$snapshot_dir/benchmark-handoff' scripts/capture-benchmark-handoff.sh"
run_and_capture soak-handoff bash -lc "cd '$repo_root' && OXIDEDNS_SOAK_HANDOFF_DIR='$snapshot_dir/soak-handoff' scripts/capture-soak-handoff.sh"
run_and_capture reproducible-build-handoff bash -lc "cd '$repo_root' && OXIDEDNS_REPRODUCIBLE_BUILD_HANDOFF_DIR='$snapshot_dir/reproducible-build-handoff' scripts/capture-reproducible-build-handoff.sh"
run_and_capture release-handoff bash -lc "cd '$repo_root' && OXIDEDNS_RELEASE_HANDOFF_DIR='$snapshot_dir/release-handoff' scripts/capture-release-handoff.sh"
run_and_capture check-sh bash -lc "cd '$repo_root' && ./scripts/check.sh"
run_and_capture fuzz-cargo-check bash -lc "cd '$repo_root' && cargo check --manifest-path fuzz/Cargo.toml"
run_and_capture cargo-deny bash -lc "cd '$repo_root' && cargo deny check"
run_and_capture unsafe-boundary-registry bash -lc "cd '$repo_root' && scripts/check-unsafe-boundaries.py"
run_and_capture unsafe-prone-dependency-gate bash -lc "cd '$repo_root' && scripts/check-unsafe-prone-dependencies.py"
run_and_capture functional-requirement-references bash -lc "cd '$repo_root' && scripts/check-functional-requirement-references.py"
run_and_capture audit-invariants bash -lc "cd '$repo_root' && scripts/audit-invariants.sh"
run_and_capture audit-readonly-runtime bash -lc "cd '$repo_root' && OXIDEDNS_READONLY_RUNTIME_ARTIFACT_DIR='$snapshot_dir/readonly-runtime-artifacts' OXIDEDNS_READONLY_RUNTIME_CONTAINER=\"\${OXIDEDNS_READONLY_RUNTIME_CONTAINER:-auto}\" scripts/audit-readonly-runtime.sh"
run_and_capture audit-safe-rust bash -lc "cd '$repo_root' && scripts/audit-safe-rust.sh"
run_and_capture audit-maintainability bash -lc "cd '$repo_root' && scripts/audit-maintainability.sh"
run_and_capture audit-spoof-evidence bash -lc "cd '$repo_root' && scripts/audit-spoof-evidence.py"
run_and_capture audit-log-fields bash -lc "cd '$repo_root' && scripts/audit-log-fields.py"
run_and_capture audit-log-lazy-formatting bash -lc "cd '$repo_root' && scripts/audit-log-lazy-formatting.py"
run_and_capture audit-unused-code bash -lc "cd '$repo_root' && OXIDEDNS_UNUSED_CODE_AUDIT_DIR='$snapshot_dir/unused-code-audit' scripts/audit-unused-code.sh"
run_and_capture audit-xot-revocation bash -lc "cd '$repo_root' && scripts/audit-xot-revocation.sh"
run_and_capture audit-dnssec-passive bash -lc "cd '$repo_root' && scripts/audit-dnssec-passive.sh"
run_and_capture perf-smoke bash -lc "cd '$repo_root' && OXIDEDNS_PERF_SMOKE_METRICS_OUT='$snapshot_dir/perf-smoke-metrics.env' OXIDEDNS_PERF_SMOKE_ARTIFACT_DIR='$snapshot_dir/perf-smoke-artifacts' scripts/perf-smoke.sh"
run_and_capture negative-responses bash -lc "cd '$repo_root' && OXIDEDNS_NEGATIVE_RESPONSE_ARTIFACT_DIR='$snapshot_dir/negative-response-artifacts' scripts/interop-negative-responses.sh"
run_and_capture notify-negative bash -lc "cd '$repo_root' && OXIDEDNS_NOTIFY_NEGATIVE_ARTIFACT_DIR='$snapshot_dir/notify-negative-artifacts' scripts/interop-notify-negative.sh"
run_and_capture tcp-truncation-retry bash -lc "cd '$repo_root' && OXIDEDNS_TCP_TRUNCATION_ARTIFACT_DIR='$snapshot_dir/tcp-truncation-artifacts' scripts/interop-tcp-truncation-retry.sh"
run_and_capture edns-behavior bash -lc "cd '$repo_root' && OXIDEDNS_EDNS_BEHAVIOR_ARTIFACT_DIR='$snapshot_dir/edns-behavior-artifacts' scripts/interop-edns-behavior.sh"
run_and_capture dns-cookie-dig bash -lc "cd '$repo_root' && OXIDEDNS_DNS_COOKIE_ARTIFACT_DIR='$snapshot_dir/dns-cookie-artifacts' scripts/interop-dns-cookie-dig.sh"
run_and_capture ixfr-notimp-fallback bash -lc "cd '$repo_root' && OXIDEDNS_IXFR_FALLBACK_ARTIFACT_DIR='$snapshot_dir/ixfr-fallback-artifacts' scripts/interop-ixfr-notimp-fallback.sh"
run_and_capture dnssec-serve bash -lc "cd '$repo_root' && OXIDEDNS_DNSSEC_SERVE_ARTIFACT_DIR='$snapshot_dir/dnssec-serve-artifacts' scripts/interop-dnssec-serve.sh"
run_and_capture dnssec-nsec3-serve bash -lc "cd '$repo_root' && OXIDEDNS_DNSSEC_NSEC3_ARTIFACT_DIR='$snapshot_dir/dnssec-nsec3-artifacts' scripts/interop-dnssec-nsec3-serve.sh"
run_and_capture rrl-udp bash -lc "cd '$repo_root' && OXIDEDNS_RRL_UDP_ARTIFACT_DIR='$snapshot_dir/rrl-udp-artifacts' scripts/interop-rrl-udp.sh"

if [[ "${OXIDEDNS_EVIDENCE_RUN_RRL_CAMPAIGN:-0}" == "1" ]]; then
  run_rrl_campaign rrl-evidence-campaign
else
  cat >"$snapshot_dir/logs/rrl-evidence-campaign-skipped.log" <<'EOF'
RRL evidence campaign was not run by default.

Set OXIDEDNS_EVIDENCE_RUN_RRL_CAMPAIGN=1 to run scripts/rrl-evidence-campaign.sh
inside this snapshot. OXIDEDNS_EVIDENCE_RRL_CAMPAIGN_ITERATIONS controls the
iteration count and defaults to 3. OXIDEDNS_EVIDENCE_RRL_CAMPAIGN_DURATION switches
the campaign to wall-clock duration mode in seconds.
EOF
fi

if [[ -n "${OXIDEDNS_PERF_BASELINE:-}" ]]; then
  run_and_capture perf-regression bash -lc \
    "cd '$repo_root' && scripts/check-perf-regression.py --candidate '$snapshot_dir/perf-smoke-metrics.env' --history '$OXIDEDNS_PERF_BASELINE' --threshold-pct '${OXIDEDNS_PERF_REGRESSION_THRESHOLD_PCT:-10}'"
else
  cat >"$snapshot_dir/logs/perf-regression-skipped.log" <<'EOF'
Performance regression comparison was not run by default.

Set OXIDEDNS_PERF_BASELINE to a whitespace-delimited history file with rows shaped
as: release metric value. OXIDEDNS_PERF_REGRESSION_THRESHOLD_PCT overrides the SRS
default 10 percent threshold.
EOF
fi

if [[ -n "${OXIDEDNS_RELEASE_NOTES:-}" ]]; then
  run_and_capture release-notes-gate bash -lc \
    "cd '$repo_root' && scripts/check-release-notes.sh '$OXIDEDNS_RELEASE_NOTES' '$snapshot_dir'"
else
  cat >"$snapshot_dir/logs/release-notes-gate-skipped.log" <<'EOF'
Release notes gate was not run by default.

Set OXIDEDNS_RELEASE_NOTES to a completed release notes markdown file to run
scripts/check-release-notes.sh against this evidence snapshot.
EOF
fi

if [[ "${OXIDEDNS_EVIDENCE_RUN_FUZZ:-0}" == "1" ]]; then
  fuzz_duration="${OXIDEDNS_EVIDENCE_FUZZ_DURATION:-10}"
  if [[ ! "$fuzz_duration" =~ ^[1-9][0-9]*$ ]]; then
    printf 'OXIDEDNS_EVIDENCE_FUZZ_DURATION must be a positive integer: %s\n' "$fuzz_duration" >&2
    exit 1
  fi
  run_and_capture fuzz-campaign bash -lc \
    "cd '$repo_root' && scripts/fuzz-campaign.sh --duration '$fuzz_duration' --evidence-dir '$snapshot_dir/fuzz-campaign'"
else
  cat >"$snapshot_dir/logs/fuzz-campaign-skipped.log" <<'EOF'
Fuzz campaigns were not run by default.

Set OXIDEDNS_EVIDENCE_RUN_FUZZ=1 to run scripts/fuzz-campaign.sh and retain its
logs, artifacts, and campaign-summary.tsv inside this snapshot.
OXIDEDNS_EVIDENCE_FUZZ_DURATION controls the per-target duration in seconds and
defaults to 10.
EOF
fi

if [[ "${OXIDEDNS_EVIDENCE_RUN_INTEROP:-0}" == "1" ]]; then
  while IFS= read -r command_line; do
    [[ -z "$command_line" || "$command_line" =~ ^# ]] && continue
    [[ "$command_line" == ./* || "$command_line" == scripts/* ]] || continue
    case "$command_line" in
      *scripts/release-evidence-snapshot.sh*|*scripts/engineering-mvp-evidence.sh*)
        continue
        ;;
      scripts/rrl-evidence-campaign.sh*)
        name="$(tr -c 'A-Za-z0-9_.-' '-' <<<"$command_line" | sed 's/^-*//; s/-*$//')"
        run_rrl_campaign "interop-$name"
        continue
        ;;
    esac
    name="$(tr -c 'A-Za-z0-9_.-' '-' <<<"$command_line" | sed 's/^-*//; s/-*$//')"
    run_and_capture "interop-$name" bash -lc "cd '$repo_root' && $command_line"
  done < <(awk '/^```sh$/ { in_block=1; next } /^```$/ && in_block { in_block=0 } in_block { print }' "$repo_root/docs/mvp-gap-register.md")
else
  cat >"$snapshot_dir/logs/interop-skipped.log" <<'EOF'
Interop scripts were not run by default.

Set OXIDEDNS_EVIDENCE_RUN_INTEROP=1 to run the interop commands listed in
docs/mvp-gap-register.md and capture each command log into this snapshot.
EOF
fi

cat <<EOF
release evidence snapshot written to $snapshot_dir
EOF
