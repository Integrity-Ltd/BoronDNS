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
scripts/perf-smoke.sh
scripts/interop-bind-axfr.sh
scripts/interop-bind-tsig-axfr.sh
scripts/interop-bind-notify-refresh.sh
EOF

run_and_capture check-sh bash -lc "cd '$repo_root' && ./scripts/check.sh"
run_and_capture fuzz-cargo-check bash -lc "cd '$repo_root' && cargo check --manifest-path fuzz/Cargo.toml"
run_and_capture audit-invariants bash -lc "cd '$repo_root' && scripts/audit-invariants.sh"
run_and_capture perf-smoke bash -lc "cd '$repo_root' && OXIDEDNS_PERF_SMOKE_METRICS_OUT='$snapshot_dir/perf-smoke-metrics.env' scripts/perf-smoke.sh"
run_and_capture interop-bind-axfr bash -lc "cd '$repo_root' && scripts/interop-bind-axfr.sh"
run_and_capture interop-bind-tsig-axfr bash -lc "cd '$repo_root' && scripts/interop-bind-tsig-axfr.sh"
run_and_capture interop-bind-notify-refresh bash -lc "cd '$repo_root' && scripts/interop-bind-notify-refresh.sh"

cat <<EOF
engineering MVP evidence snapshot written to $snapshot_dir
EOF
