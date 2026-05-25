#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/rrl-evidence-campaign.sh [OPTIONS]

Run repeated RRL UDP interop evidence and retain command logs.

Options:
  --iterations COUNT    Number of interop runs to execute (default: 3)
  --duration SECONDS    Run completed iterations until this wall-clock duration is reached
  --evidence-dir DIR    Output directory (default: target/rrl-evidence/<timestamp>)
  --dry-run             Write config and print commands without running the interop script
  --list-config         Print resolved configuration and exit without writing files
  -h, --help            Show this help

Environment:
  BASH_BIN              Bash executable to use for the interop script (default: current bash)
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
interop_script="$repo_root/scripts/interop-rrl-udp.sh"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
evidence_dir="$repo_root/target/rrl-evidence/$timestamp"
bash_bin="${BASH_BIN:-${BASH:-bash}}"
iterations=3
duration=""
iterations_set=0
duration_set=0
dry_run=0
list_config=0

require_positive_integer() {
  local name="$1"
  local value="$2"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "$name must be a positive integer: $value"
}

parse_args() {
  while (($# > 0)); do
    case "$1" in
      --iterations)
        (($# >= 2)) || die "--iterations requires a value"
        iterations="$2"
        iterations_set=1
        shift 2
        ;;
      --duration)
        (($# >= 2)) || die "--duration requires a value"
        duration="$2"
        duration_set=1
        shift 2
        ;;
      --evidence-dir)
        (($# >= 2)) || die "--evidence-dir requires a value"
        evidence_dir="$2"
        shift 2
        ;;
      --dry-run)
        dry_run=1
        shift
        ;;
      --list-config)
        list_config=1
        shift
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      --)
        shift
        (($# == 0)) || die "unexpected positional argument: $1"
        ;;
      -*)
        die "unknown option: $1"
        ;;
      *)
        die "unexpected positional argument: $1"
        ;;
    esac
  done
}

resolve_config() {
  [[ "$evidence_dir" == /* ]] || evidence_dir="$repo_root/$evidence_dir"
  [[ -f "$interop_script" ]] || die "missing interop script: $interop_script"
  require_positive_integer "--iterations" "$iterations"
  if ((duration_set)); then
    require_positive_integer "--duration" "$duration"
  fi
  if ((duration_set && iterations_set)); then
    die "use --iterations or --duration, not both"
  fi
}

print_config() {
  local mode="iterations"
  if ((duration_set)); then
    mode="duration"
  fi
  printf 'repo_root=%s\n' "$repo_root"
  printf 'interop_script=%s\n' "$interop_script"
  printf 'evidence_dir=%s\n' "$evidence_dir"
  printf 'mode=%s\n' "$mode"
  printf 'iterations=%s\n' "$iterations"
  printf 'duration_seconds=%s\n' "${duration:-}"
  printf 'dry_run=%s\n' "$dry_run"
  printf 'bash=%s\n' "$bash_bin"
  printf 'command='
  printf '%q ' "$bash_bin" "$interop_script"
  printf '\n'
}

record_versions() {
  local versions_file="$1"
  {
    printf 'date_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'repo_root=%s\n' "$repo_root"
    printf 'commit=%s\n' "$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf 'unknown')"
    printf 'branch=%s\n' "$(git -C "$repo_root" branch --show-current 2>/dev/null || printf 'unknown')"
    printf 'uname=%s\n' "$(uname -a)"
    printf 'bash=%s\n' "$bash_bin"
    if command -v "$bash_bin" >/dev/null 2>&1; then
      "$bash_bin" --version | head -1
    else
      printf '%s not found on PATH\n' "$bash_bin"
    fi
    for tool in cargo rustc python3 curl shellcheck; do
      if command -v "$tool" >/dev/null 2>&1; then
        "$tool" --version 2>&1 | head -1
      else
        printf '%s not found on PATH\n' "$tool"
      fi
    done
  } >"$versions_file"
}

write_config() {
  local config_file="$1"
  print_config >"$config_file"
  {
    printf 'interop_script_sha256='
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$interop_script" | awk '{ print $1 }'
    else
      printf 'sha256sum not found\n'
    fi
  } >>"$config_file"
}

write_git_state() {
  git -C "$repo_root" status --short >"$evidence_dir/git-status.txt"
  git -C "$repo_root" diff --stat >"$evidence_dir/git-diff-stat.txt"
  git -C "$repo_root" diff --check >"$evidence_dir/git-diff-check.txt" 2>&1 || true
}

write_readme() {
  cat >"$evidence_dir/README.md" <<EOF
# OxideDNS RRL Evidence Campaign

- Created UTC: $timestamp
- Repository: $repo_root
- Interop script: $interop_script

This retained artifact wraps scripts/interop-rrl-udp.sh and records repeated
runtime UDP RRL drop/slip evidence. Any failed interop run fails the campaign.
EOF
}

run_one() {
  local run_number="$1"
  local run_id
  local run_log
  local command_file
  local artifact_dir
  local status
  local started
  local finished
  local -a cmd

  printf -v run_id 'run-%03d' "$run_number"
  run_log="$evidence_dir/logs/$run_id.log"
  command_file="$evidence_dir/logs/$run_id.command"
  artifact_dir="$evidence_dir/artifacts/$run_id"
  cmd=("$bash_bin" "$interop_script")
  mkdir -p "$artifact_dir"

  {
    printf 'run=%s\n' "$run_id"
    printf 'command='
    printf '%q ' "${cmd[@]}"
    printf '\n'
  } >"$command_file"

  printf 'Running %s; log: %s\n' "$run_id" "$run_log"
  started="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  set +e
  (
    cd "$repo_root"
    OXIDEDNS_RRL_UDP_ARTIFACT_DIR="$artifact_dir" "${cmd[@]}"
  ) >"$run_log" 2>&1
  status=$?
  set -e
  finished="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

  {
    printf 'run=%s status=%s started=%s finished=%s log=%s\n' \
      "$run_id" "$status" "$started" "$finished" "$run_log"
  } >>"$evidence_dir/summary.txt"

  if ((status != 0)); then
    printf 'RRL evidence %s failed with exit %s\n' "$run_id" "$status" >&2
    printf -- '---- %s tail ----\n' "$run_log" >&2
    tail -160 "$run_log" >&2 || true
    return "$status"
  fi
}

run_campaign() {
  local run_count=0
  local start_epoch
  local elapsed

  start_epoch="$(date +%s)"
  : >"$evidence_dir/summary.txt"

  if ((duration_set)); then
    while true; do
      run_count=$((run_count + 1))
      run_one "$run_count"
      elapsed=$(($(date +%s) - start_epoch))
      ((elapsed >= duration)) && break
    done
  else
    for ((run_count = 1; run_count <= iterations; run_count++)); do
      run_one "$run_count"
    done
  fi

  printf 'rrl_runs_completed=%s\n' "$run_count" >>"$evidence_dir/summary.txt"
}

main() {
  parse_args "$@"
  resolve_config

  if ((list_config)); then
    print_config
    exit 0
  fi

  mkdir -p "$evidence_dir/logs"
  write_config "$evidence_dir/config.txt"
  record_versions "$evidence_dir/tool-versions.txt"
  write_git_state
  write_readme

  if ((dry_run)); then
    printf 'DRY RUN: would run RRL evidence campaign with this configuration:\n'
    print_config
    printf 'rrl evidence dry-run files written to %s\n' "$evidence_dir"
    exit 0
  fi

  command -v "$bash_bin" >/dev/null 2>&1 || die "$bash_bin not found on PATH"
  run_campaign
  printf 'rrl evidence retained at %s\n' "$evidence_dir"
}

main "$@"
