#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/evidence-artifacts.sh"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_root="${OXIDEDNS_ENGINEERING_MVP_EVIDENCE_DIR:-$repo_root/target/evidence/engineering-mvp}"
snapshot_dir="$evidence_root/$timestamp"
mkdir -p "$snapshot_dir/logs" "$snapshot_dir/interop-primary-versions"
printf 'source_path\tsnapshot_path\n' >"$snapshot_dir/interop-primary-versions/INDEX.tsv"

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

cat >"$snapshot_dir/README.md" <<EOF
# OxideDNS Engineering MVP Evidence Snapshot

- Created UTC: $timestamp
- Repository: $repo_root
- Commit: $(git -C "$repo_root" rev-parse HEAD)
- Branch: $(git -C "$repo_root" branch --show-current)

This snapshot captures the narrow Engineering MVP evidence profile. It is not
the full SRS ODS-VER-008 acceptance matrix.

Successful real-primary interop runs copy their primary-version artifacts to
interop-primary-versions/ with an INDEX.tsv mapping source and snapshot paths.
EOF

git -C "$repo_root" status --short >"$snapshot_dir/git-status.txt"
git -C "$repo_root" log --oneline -20 >"$snapshot_dir/git-log.txt"
git -C "$repo_root" diff --stat >"$snapshot_dir/git-diff-stat.txt"
git -C "$repo_root" diff --check >"$snapshot_dir/git-diff-check.txt"

cat >"$snapshot_dir/commands.txt" <<'EOF'
./scripts/check.sh
cargo check --manifest-path fuzz/Cargo.toml
scripts/audit-invariants.sh
scripts/audit-readonly-runtime.sh
scripts/audit-log-fields.py
scripts/audit-log-lazy-formatting.py
scripts/audit-unused-code.sh
scripts/capture-log-evidence.sh
scripts/capture-signal-evidence.sh
scripts/capture-health-metrics-evidence.sh
scripts/capture-malformed-query-evidence.sh
scripts/capture-portability-evidence.sh
scripts/capture-resource-evidence.sh
scripts/perf-smoke.sh
scripts/interop-negative-responses.sh
scripts/interop-notify-negative.sh
scripts/interop-tcp-truncation-retry.sh
scripts/interop-edns-behavior.sh
scripts/interop-dns-cookie-dig.sh
scripts/interop-ixfr-notimp-fallback.sh
scripts/interop-unknown-rr.sh
scripts/interop-unknown-rr-bad-transfer.sh
scripts/interop-bind-ixfr-refresh.sh
scripts/interop-dnssec-serve.sh
scripts/interop-dnssec-nsec3-serve.sh
scripts/interop-rrl-udp.sh
scripts/interop-bind-axfr.sh
scripts/interop-bind-tsig-axfr.sh
scripts/interop-bind-notify-refresh.sh
EOF

run_and_capture check-sh bash -lc "cd '$repo_root' && ./scripts/check.sh"
run_and_capture log-evidence bash -lc "cd '$repo_root' && OXIDEDNS_LOG_EVIDENCE_DIR='$snapshot_dir/log-evidence' scripts/capture-log-evidence.sh"
run_and_capture signal-evidence bash -lc "cd '$repo_root' && OXIDEDNS_SIGNAL_EVIDENCE_DIR='$snapshot_dir/signal-evidence' scripts/capture-signal-evidence.sh"
run_and_capture health-metrics-evidence bash -lc "cd '$repo_root' && OXIDEDNS_HEALTH_METRICS_EVIDENCE_DIR='$snapshot_dir/health-metrics-evidence' scripts/capture-health-metrics-evidence.sh"
run_and_capture malformed-query-evidence bash -lc "cd '$repo_root' && OXIDEDNS_MALFORMED_QUERY_EVIDENCE_DIR='$snapshot_dir/malformed-query-evidence' scripts/capture-malformed-query-evidence.sh"
run_and_capture portability-evidence bash -lc "cd '$repo_root' && OXIDEDNS_PORTABILITY_EVIDENCE_DIR='$snapshot_dir/portability-evidence' scripts/capture-portability-evidence.sh"
run_and_capture resource-evidence bash -lc "cd '$repo_root' && OXIDEDNS_RESOURCE_EVIDENCE_DIR='$snapshot_dir/resource-evidence' scripts/capture-resource-evidence.sh"
run_and_capture fuzz-cargo-check bash -lc "cd '$repo_root' && cargo check --manifest-path fuzz/Cargo.toml"
run_and_capture audit-invariants bash -lc "cd '$repo_root' && scripts/audit-invariants.sh"
run_and_capture audit-readonly-runtime bash -lc "cd '$repo_root' && OXIDEDNS_READONLY_RUNTIME_ARTIFACT_DIR='$snapshot_dir/readonly-runtime-artifacts' OXIDEDNS_READONLY_RUNTIME_CONTAINER=\"\${OXIDEDNS_READONLY_RUNTIME_CONTAINER:-auto}\" scripts/audit-readonly-runtime.sh"
run_and_capture audit-spoof-evidence bash -lc "cd '$repo_root' && scripts/audit-spoof-evidence.py"
run_and_capture audit-log-fields bash -lc "cd '$repo_root' && scripts/audit-log-fields.py"
run_and_capture audit-log-lazy-formatting bash -lc "cd '$repo_root' && scripts/audit-log-lazy-formatting.py"
run_and_capture audit-unused-code bash -lc "cd '$repo_root' && OXIDEDNS_UNUSED_CODE_AUDIT_DIR='$snapshot_dir/unused-code-audit' scripts/audit-unused-code.sh"
run_and_capture perf-smoke bash -lc "cd '$repo_root' && OXIDEDNS_PERF_SMOKE_METRICS_OUT='$snapshot_dir/perf-smoke-metrics.env' OXIDEDNS_PERF_SMOKE_ARTIFACT_DIR='$snapshot_dir/perf-smoke-artifacts' scripts/perf-smoke.sh"
run_and_capture negative-responses bash -lc "cd '$repo_root' && OXIDEDNS_NEGATIVE_RESPONSE_ARTIFACT_DIR='$snapshot_dir/negative-response-artifacts' scripts/interop-negative-responses.sh"
run_and_capture notify-negative bash -lc "cd '$repo_root' && OXIDEDNS_NOTIFY_NEGATIVE_ARTIFACT_DIR='$snapshot_dir/notify-negative-artifacts' scripts/interop-notify-negative.sh"
run_and_capture tcp-truncation-retry bash -lc "cd '$repo_root' && OXIDEDNS_TCP_TRUNCATION_ARTIFACT_DIR='$snapshot_dir/tcp-truncation-artifacts' scripts/interop-tcp-truncation-retry.sh"
run_and_capture edns-behavior bash -lc "cd '$repo_root' && OXIDEDNS_EDNS_BEHAVIOR_ARTIFACT_DIR='$snapshot_dir/edns-behavior-artifacts' scripts/interop-edns-behavior.sh"
run_and_capture dns-cookie-dig bash -lc "cd '$repo_root' && OXIDEDNS_DNS_COOKIE_ARTIFACT_DIR='$snapshot_dir/dns-cookie-artifacts' scripts/interop-dns-cookie-dig.sh"
run_and_capture ixfr-notimp-fallback bash -lc "cd '$repo_root' && OXIDEDNS_IXFR_FALLBACK_ARTIFACT_DIR='$snapshot_dir/ixfr-fallback-artifacts' scripts/interop-ixfr-notimp-fallback.sh"
run_and_capture unknown-rr bash -lc "cd '$repo_root' && OXIDEDNS_UNKNOWN_RR_ARTIFACT_DIR='$snapshot_dir/unknown-rr-artifacts' scripts/interop-unknown-rr.sh"
run_and_capture unknown-rr-bad-transfer bash -lc "cd '$repo_root' && OXIDEDNS_UNKNOWN_RR_BAD_ARTIFACT_DIR='$snapshot_dir/unknown-rr-bad-transfer-artifacts' scripts/interop-unknown-rr-bad-transfer.sh"
run_and_capture interop-bind-ixfr-refresh bash -lc "cd '$repo_root' && OXIDEDNS_BIND_IXFR_ARTIFACT_DIR='$snapshot_dir/bind-ixfr-artifacts' scripts/interop-bind-ixfr-refresh.sh"
run_and_capture dnssec-serve bash -lc "cd '$repo_root' && OXIDEDNS_DNSSEC_SERVE_ARTIFACT_DIR='$snapshot_dir/dnssec-serve-artifacts' scripts/interop-dnssec-serve.sh"
run_and_capture dnssec-nsec3-serve bash -lc "cd '$repo_root' && OXIDEDNS_DNSSEC_NSEC3_ARTIFACT_DIR='$snapshot_dir/dnssec-nsec3-artifacts' scripts/interop-dnssec-nsec3-serve.sh"
run_and_capture rrl-udp bash -lc "cd '$repo_root' && OXIDEDNS_RRL_UDP_ARTIFACT_DIR='$snapshot_dir/rrl-udp-artifacts' scripts/interop-rrl-udp.sh"
run_and_capture interop-bind-axfr bash -lc "cd '$repo_root' && scripts/interop-bind-axfr.sh"
run_and_capture interop-bind-tsig-axfr bash -lc "cd '$repo_root' && OXIDEDNS_BIND_TSIG_AXFR_ARTIFACT_DIR='$snapshot_dir/bind-tsig-axfr-artifacts' scripts/interop-bind-tsig-axfr.sh"
run_and_capture interop-bind-notify-refresh bash -lc "cd '$repo_root' && scripts/interop-bind-notify-refresh.sh"

cat <<EOF
engineering MVP evidence snapshot written to $snapshot_dir
EOF
