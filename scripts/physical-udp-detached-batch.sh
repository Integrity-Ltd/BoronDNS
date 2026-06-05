#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runs_root="${OXIDEDNS_PHYSICAL_DETACHED_ROOT:-$repo_root/target/physical-detached-runs}"
harness="${OXIDEDNS_PHYSICAL_DETACHED_HARNESS:-$repo_root/scripts/physical-udp-knot-comparison.sh}"
server_ssh="${OXIDEDNS_PHYSICAL_SERVER_SSH:-oxidedns-1}"
player_ssh="${OXIDEDNS_PHYSICAL_PLAYER_SSH:-oxidegun-1}"
server_root="${OXIDEDNS_PHYSICAL_SERVER_ROOT:-~/oxidedns}"
player_workdir="${OXIDEDNS_PHYSICAL_PLAYER_WORKDIR:-~/oxidedns-tools/bench}"
interface="${OXIDEDNS_PHYSICAL_INTERFACE:-eno1np0}"

usage() {
    cat >&2 <<EOF
Usage:
  $0 start [harness-args...]
  $0 status RUN_DIR

Environment:
  OXIDEDNS_PHYSICAL_* variables are passed through to the detached harness.
  OXIDEDNS_PHYSICAL_DETACHED_ROOT overrides the local run directory root.
EOF
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'missing required tool: %s\n' "$1" >&2
        exit 69
    fi
}

record_command() {
    local run_dir="$1"
    shift

    {
        printf 'cwd=%s\n' "$repo_root"
        printf 'harness=%s\n' "$harness"
        printf 'args='
        printf '%q ' "$@"
        printf '\n'
        printf 'server_ssh=%s\n' "$server_ssh"
        printf 'player_ssh=%s\n' "$player_ssh"
        printf 'server_root=%s\n' "$server_root"
        printf 'player_workdir=%s\n' "$player_workdir"
        printf 'interface=%s\n' "$interface"
        if git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
            printf 'git_head=%s\n' "$(git -C "$repo_root" rev-parse HEAD)"
            printf 'git_status_short<<EOF\n'
            git -C "$repo_root" status --short
            printf 'EOF\n'
        fi
    } >"$run_dir/command.txt"
    env | LC_ALL=C sort | awk -F= '$1 ~ /^OXIDEDNS_PHYSICAL_/ { print }' >"$run_dir/environment.txt"
}

start_run() {
    local timestamp run_dir monitor_pid

    require_tool nohup
    require_tool ssh

    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    run_dir="${OXIDEDNS_PHYSICAL_DETACHED_RUN_DIR:-$runs_root/$timestamp}"
    if [[ -e "$run_dir" ]]; then
        printf 'detached run directory already exists: %s\n' "$run_dir" >&2
        exit 73
    fi
    mkdir -p "$run_dir"
    record_command "$run_dir" "$@"
    date -u +%Y-%m-%dT%H:%M:%SZ >"$run_dir/submitted-at.txt"
    printf 'starting\n' >"$run_dir/status"

    nohup bash -s -- "$repo_root" "$run_dir" "$harness" "$server_ssh" "$player_ssh" "$interface" "$@" >"$run_dir/monitor.log" 2>&1 <<'MONITOR' &
set -euo pipefail

repo_root="$1"
run_dir="$2"
harness="$3"
server_ssh="$4"
player_ssh="$5"
interface="$6"
shift 6

cd "$repo_root"
date -u +%Y-%m-%dT%H:%M:%SZ >"$run_dir/started-at.txt"
printf 'running\n' >"$run_dir/status"
ssh_options=(
	-o BatchMode=yes
	-o ConnectTimeout=10
	-o ServerAliveInterval=5
	-o ServerAliveCountMax=1
)

set +e
"$harness" "$@" >"$run_dir/harness.log" 2>&1
harness_status=$?
set -e

printf '%s\n' "$harness_status" >"$run_dir/exit-code"
date -u +%Y-%m-%dT%H:%M:%SZ >"$run_dir/finished-at.txt"

artifact_dir="$(awk -F= '$1 == "artifact_dir" { value = $2 } END { print value }' "$run_dir/harness.log")"
if [[ -n "$artifact_dir" ]]; then
	printf '%s\n' "$artifact_dir" >"$run_dir/remote-artifact-dir.txt"
	ssh "${ssh_options[@]}" "$server_ssh" bash -s -- "$artifact_dir" >"$run_dir/summary.tsv" 2>"$run_dir/summary-fetch.err" <<'REMOTE' || true
set -euo pipefail
artifact_dir="$1"
cat "$artifact_dir/summary.tsv"
REMOTE
fi

{
	date -u +%Y-%m-%dT%H:%M:%SZ
	ssh "${ssh_options[@]}" "$server_ssh" bash -s -- "$interface" <<'REMOTE'
set -euo pipefail
iface="$1"
printf 'net.core.wmem_max='
sysctl -n net.core.wmem_max
ip -o link show dev "$iface" || true
tc qdisc show dev "$iface" || true
pgrep -a oxidedns || true
pgrep -a knotd || true
pgrep -a perf || true
REMOTE
} >"$run_dir/server-cleanup-check.txt" 2>&1 || true

{
	date -u +%Y-%m-%dT%H:%M:%SZ
	ssh "${ssh_options[@]}" "$player_ssh" bash -s <<'REMOTE'
set -euo pipefail
pgrep -a kxdpgun || true
find ~/oxidedns-tools/bench -maxdepth 1 -type d -name ".oxidedns-physical-*" -print | head
REMOTE
} >"$run_dir/player-cleanup-check.txt" 2>&1 || true

if [[ "$harness_status" == 0 ]]; then
    printf 'passed\n' >"$run_dir/status"
else
    printf 'failed\n' >"$run_dir/status"
fi
exit "$harness_status"
MONITOR
    monitor_pid="$!"
    printf '%s\n' "$monitor_pid" >"$run_dir/monitor.pid"

    printf 'detached_run_dir=%s\n' "$run_dir"
    printf 'monitor_pid=%s\n' "$monitor_pid"
    printf 'status_file=%s/status\n' "$run_dir"
    printf 'harness_log=%s/harness.log\n' "$run_dir"
    printf 'summary_file=%s/summary.tsv\n' "$run_dir"
}

status_run() {
    local run_dir="$1"
    local pid=""

    if [[ ! -d "$run_dir" ]]; then
        printf 'detached run directory not found: %s\n' "$run_dir" >&2
        exit 66
    fi
    if [[ -f "$run_dir/monitor.pid" ]]; then
        pid="$(<"$run_dir/monitor.pid")"
    fi

    printf 'detached_run_dir=%s\n' "$run_dir"
    if [[ -n "$pid" ]]; then
        printf 'monitor_pid=%s\n' "$pid"
        if kill -0 "$pid" >/dev/null 2>&1; then
            printf 'monitor_alive=true\n'
        else
            printf 'monitor_alive=false\n'
        fi
    fi
    if [[ -f "$run_dir/status" ]]; then
        printf 'status=%s\n' "$(<"$run_dir/status")"
    else
        printf 'status=unknown\n'
    fi
    if [[ -f "$run_dir/exit-code" ]]; then
        printf 'exit_code=%s\n' "$(<"$run_dir/exit-code")"
    fi
    if [[ -f "$run_dir/remote-artifact-dir.txt" ]]; then
        printf 'remote_artifact_dir=%s\n' "$(<"$run_dir/remote-artifact-dir.txt")"
    fi
    printf 'harness_log=%s/harness.log\n' "$run_dir"
    printf 'monitor_log=%s/monitor.log\n' "$run_dir"
    printf 'server_cleanup_check=%s/server-cleanup-check.txt\n' "$run_dir"
    printf 'player_cleanup_check=%s/player-cleanup-check.txt\n' "$run_dir"
    if [[ -s "$run_dir/summary.tsv" ]]; then
        printf 'summary_file=%s/summary.tsv\n' "$run_dir"
        cat "$run_dir/summary.tsv"
    fi
}

command="${1:-start}"
case "$command" in
start)
    shift || true
    start_run "$@"
    ;;
status)
    if [[ "$#" != 2 ]]; then
        usage
        exit 64
    fi
    status_run "$2"
    ;;
-h | --help | help)
    usage
    ;;
*)
    usage
    exit 64
    ;;
esac
