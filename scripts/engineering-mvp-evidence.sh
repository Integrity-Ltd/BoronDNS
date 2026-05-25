#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_root="${OXIDEDNS_ENGINEERING_MVP_EVIDENCE_DIR:-$repo_root/target/evidence/engineering-mvp}"
command_timeout_seconds="${OXIDEDNS_ENGINEERING_MVP_COMMAND_TIMEOUT_SECONDS:-300}"
snapshot_dir="$evidence_root/$timestamp"
mkdir -p "$snapshot_dir/logs"

run_and_capture() {
    local name="$1"
    shift
    local log="$snapshot_dir/logs/$name.log"

    set +e
    {
        printf '$'
        printf ' %q' "$@"
        printf '\n\n'
        timeout --preserve-status "${command_timeout_seconds}s" "$@"
    } >"$log" 2>&1
    local status=$?
    set -e

    return "$status"
}

cat >"$snapshot_dir/README.md" <<EOF
# OxideDNS Engineering MVP Evidence Snapshot

- Created UTC: $timestamp
- Repository: $repo_root
- Commit: $(git -C "$repo_root" rev-parse HEAD)
- Branch: $(git -C "$repo_root" branch --show-current)
- Per-command timeout: ${command_timeout_seconds}s

This snapshot captures the narrow Engineering MVP evidence profile. It is not
the full SRS ODS-VER-008 acceptance matrix.

The default profile runs only bounded local Engineering MVP evidence commands.
Long-running evidence, real-primary interop sweeps, release benchmark/soak
handoffs, signed artifact production, and external acceptance are deferred to
release/operations profiles and are not executed by this script.
EOF

git -C "$repo_root" status --short >"$snapshot_dir/git-status.txt"
git -C "$repo_root" log --oneline -20 >"$snapshot_dir/git-log.txt"
git -C "$repo_root" diff --stat >"$snapshot_dir/git-diff-stat.txt"
git -C "$repo_root" diff --check >"$snapshot_dir/git-diff-check.txt"

cat >"$snapshot_dir/commands.txt" <<'EOF'
scripts/check-security-policy.sh
scripts/capture-cli-evidence.sh
scripts/audit-unused-code.sh
scripts/check-functional-requirement-references.py
scripts/capture-log-evidence.sh
scripts/capture-signal-evidence.sh
scripts/capture-health-metrics-evidence.sh
scripts/capture-malformed-query-evidence.sh
scripts/capture-portability-evidence.sh
scripts/capture-resource-evidence.sh
scripts/capture-coverage-evidence.sh
scripts/capture-unsafe-dependency-evidence.sh
scripts/capture-interface-compatibility-evidence.sh
EOF

cat >"$snapshot_dir/deferred-not-run.txt" <<'EOF'
The Engineering MVP evidence profile does not execute these broader
release/operations commands:

./scripts/check.sh
cargo check --manifest-path fuzz/Cargo.toml
scripts/audit-invariants.sh
scripts/audit-readonly-runtime.sh
scripts/audit-spoof-evidence.py
scripts/audit-log-fields.py
scripts/audit-log-lazy-formatting.py
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

run_and_capture security-policy bash -lc "cd '$repo_root' && scripts/check-security-policy.sh"
run_and_capture cli-evidence bash -lc "cd '$repo_root' && OXIDEDNS_CLI_EVIDENCE_DIR='$snapshot_dir/cli-evidence' scripts/capture-cli-evidence.sh"
run_and_capture log-evidence bash -lc "cd '$repo_root' && OXIDEDNS_LOG_EVIDENCE_DIR='$snapshot_dir/log-evidence' scripts/capture-log-evidence.sh"
run_and_capture signal-evidence bash -lc "cd '$repo_root' && OXIDEDNS_SIGNAL_EVIDENCE_DIR='$snapshot_dir/signal-evidence' scripts/capture-signal-evidence.sh"
run_and_capture health-metrics-evidence bash -lc "cd '$repo_root' && OXIDEDNS_HEALTH_METRICS_EVIDENCE_DIR='$snapshot_dir/health-metrics-evidence' scripts/capture-health-metrics-evidence.sh"
run_and_capture malformed-query-evidence bash -lc "cd '$repo_root' && OXIDEDNS_MALFORMED_QUERY_EVIDENCE_DIR='$snapshot_dir/malformed-query-evidence' scripts/capture-malformed-query-evidence.sh"
run_and_capture portability-evidence bash -lc "cd '$repo_root' && OXIDEDNS_PORTABILITY_EVIDENCE_DIR='$snapshot_dir/portability-evidence' scripts/capture-portability-evidence.sh"
run_and_capture resource-evidence bash -lc "cd '$repo_root' && OXIDEDNS_RESOURCE_EVIDENCE_DIR='$snapshot_dir/resource-evidence' scripts/capture-resource-evidence.sh"
run_and_capture coverage-evidence bash -lc "cd '$repo_root' && OXIDEDNS_COVERAGE_EVIDENCE_DIR='$snapshot_dir/coverage-evidence' scripts/capture-coverage-evidence.sh"
run_and_capture unsafe-dependency-evidence bash -lc "cd '$repo_root' && OXIDEDNS_UNSAFE_DEPENDENCY_EVIDENCE_DIR='$snapshot_dir/unsafe-dependency-evidence' scripts/capture-unsafe-dependency-evidence.sh"
run_and_capture interface-compatibility-evidence bash -lc "cd '$repo_root' && OXIDEDNS_INTERFACE_COMPATIBILITY_DIR='$snapshot_dir/interface-compatibility-evidence' scripts/capture-interface-compatibility-evidence.sh"
run_and_capture audit-unused-code bash -lc "cd '$repo_root' && OXIDEDNS_UNUSED_CODE_AUDIT_DIR='$snapshot_dir/unused-code-audit' scripts/audit-unused-code.sh"
run_and_capture functional-requirement-references bash -lc "cd '$repo_root' && scripts/check-functional-requirement-references.py"

cat <<EOF
engineering MVP evidence snapshot written to $snapshot_dir
EOF
