#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_root="${OXIDEDNS_EVIDENCE_DIR:-$repo_root/target/evidence}"
snapshot_dir="$evidence_root/$timestamp"
mkdir -p "$snapshot_dir/logs"

run_and_capture() {
  local name="$1"
  shift
  local log="$snapshot_dir/logs/$name.log"
  {
    printf '$'
    printf ' %q' "$@"
    printf '\n\n'
    "$@"
  } >"$log" 2>&1
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

cat >"$snapshot_dir/README.md" <<EOF
# OxideDNS Release Evidence Snapshot

- Created UTC: $timestamp
- Repository: $repo_root
- Commit: $(git -C "$repo_root" rev-parse HEAD)
- Branch: $(git -C "$repo_root" branch --show-current)

This directory contains command logs captured for release review, including
safe-Rust and maintainability audit output. It is an evidence collection
artifact, not a substitute for the SRS traceability matrix, 24-hour fuzzing
campaigns, soak testing, or production benchmark reports.
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
record_version docker docker --version
record_version dig dig -v
record_version curl curl --version
record_version python3 python3 --version

{
  printf '# OxideDNS Verification Commands\n\n'
  awk '/^```sh$/ { in_block=1 } in_block { print } /^```$/ && in_block { in_block=0 }' \
    "$repo_root/docs/mvp-gap-register.md"
} >"$snapshot_dir/verification-commands.md"

run_and_capture check-sh bash -lc "cd '$repo_root' && ./scripts/check.sh"
run_and_capture fuzz-cargo-check bash -lc "cd '$repo_root' && cargo check --manifest-path fuzz/Cargo.toml"
run_and_capture cargo-deny bash -lc "cd '$repo_root' && cargo deny check"
run_and_capture audit-invariants bash -lc "cd '$repo_root' && scripts/audit-invariants.sh"
run_and_capture audit-safe-rust bash -lc "cd '$repo_root' && scripts/audit-safe-rust.sh"
run_and_capture audit-maintainability bash -lc "cd '$repo_root' && scripts/audit-maintainability.sh"
run_and_capture audit-xot-revocation bash -lc "cd '$repo_root' && scripts/audit-xot-revocation.sh"

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
logs and artifacts inside this snapshot. OXIDEDNS_EVIDENCE_FUZZ_DURATION controls
the per-target duration in seconds and defaults to 10.
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
