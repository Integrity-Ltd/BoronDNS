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
  SSH_AUTH_SOCK is passed through when set so systemd-launched monitors can SSH.
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
    local name value
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
    env | LC_ALL=C sort | awk -F= '$1 ~ /^OXIDEDNS_PHYSICAL_/ || $1 == "SSH_AUTH_SOCK" || $1 == "SSH_AGENT_PID" { print }' >"$run_dir/environment.txt"
    while IFS='=' read -r name value; do
        if [[ "$name" =~ ^OXIDEDNS_PHYSICAL_ || "$name" == "SSH_AUTH_SOCK" || "$name" == "SSH_AGENT_PID" ]]; then
            printf 'export %s=%q\n' "$name" "$value"
        fi
    done < <(env | LC_ALL=C sort) >"$run_dir/environment.sh"
    chmod 600 "$run_dir/environment.sh"
}

start_run() {
    local launcher monitor_pid timestamp unit run_dir

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

    cat >"$run_dir/monitor.sh" <<'MONITOR'
#!/usr/bin/env bash
set -euo pipefail

repo_root="$1"
run_dir="$2"
harness="$3"
server_ssh="$4"
player_ssh="$5"
interface="$6"
shift 6

cd "$repo_root"
exec >>"$run_dir/monitor.log" 2>&1
# shellcheck source=/dev/null
source "$run_dir/environment.sh"
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

mapfile -t artifact_dirs < <(awk -F= '$1 == "artifact_dir" { print $2 }' "$run_dir/harness.log")
if ((${#artifact_dirs[@]} > 0)); then
	printf '%s\n' "${artifact_dirs[@]}" >"$run_dir/remote-artifact-dir.txt"
	: >"$run_dir/summary.tsv"
	: >"$run_dir/summary-fetch.err"
	for artifact_index in "${!artifact_dirs[@]}"; do
		artifact_dir="${artifact_dirs[$artifact_index]}"
		tmp_summary="$run_dir/summary.$artifact_index.tsv"
		ssh "${ssh_options[@]}" "$server_ssh" bash -s -- "$artifact_dir" >"$tmp_summary" 2>>"$run_dir/summary-fetch.err" <<'REMOTE' || true
set -euo pipefail
artifact_dir="$1"
cat "$artifact_dir/summary.tsv"
REMOTE
		if [[ -s "$tmp_summary" ]]; then
			if [[ ! -s "$run_dir/summary.tsv" ]]; then
				cat "$tmp_summary" >>"$run_dir/summary.tsv"
			else
				tail -n +2 "$tmp_summary" >>"$run_dir/summary.tsv"
			fi
		fi
	done
	if [[ -s "$run_dir/summary.tsv" && -x "$repo_root/scripts/summarize-physical-loss-bands.py" ]]; then
		"$repo_root/scripts/summarize-physical-loss-bands.py" "$run_dir/summary.tsv" >"$run_dir/loss-bands.tsv" 2>"$run_dir/loss-bands.err" || true
	fi
fi

{
	date -u +%Y-%m-%dT%H:%M:%SZ
	ssh "${ssh_options[@]}" "$server_ssh" bash -s -- "$interface" <<'REMOTE'
set -euo pipefail
iface="$1"
printf 'net.core.wmem_max='
sysctl -n net.core.wmem_max
printf 'net.core.rmem_max='
sysctl -n net.core.rmem_max
ip -o link show dev "$iface" || true
tc qdisc show dev "$iface" || true
pgrep -a oxidedns || true
pgrep -a knotd || true
pgrep -a nsd || true
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
    chmod +x "$run_dir/monitor.sh"
    launcher="${OXIDEDNS_PHYSICAL_DETACHED_LAUNCHER:-auto}"
    if [[ "$launcher" != "nohup" ]] && command -v systemd-run >/dev/null 2>&1; then
        unit="oxidedns-physical-${timestamp}-$$"
        if systemd-run --user --quiet --unit "$unit" --collect "$run_dir/monitor.sh" "$repo_root" "$run_dir" "$harness" "$server_ssh" "$player_ssh" "$interface" "$@" >"$run_dir/launcher.log" 2>&1; then
            printf 'systemd-run\n' >"$run_dir/launcher"
            printf '%s\n' "$unit" >"$run_dir/systemd-unit"
        else
            if [[ "$launcher" != "auto" ]]; then
                cat "$run_dir/launcher.log" >&2
                exit 70
            fi
            require_tool nohup
            nohup "$run_dir/monitor.sh" "$repo_root" "$run_dir" "$harness" "$server_ssh" "$player_ssh" "$interface" "$@" </dev/null >"$run_dir/launcher.log" 2>&1 &
            monitor_pid="$!"
            printf 'nohup\n' >"$run_dir/launcher"
            printf '%s\n' "$monitor_pid" >"$run_dir/monitor.pid"
        fi
    else
        require_tool nohup
        nohup "$run_dir/monitor.sh" "$repo_root" "$run_dir" "$harness" "$server_ssh" "$player_ssh" "$interface" "$@" </dev/null >"$run_dir/launcher.log" 2>&1 &
        monitor_pid="$!"
        printf 'nohup\n' >"$run_dir/launcher"
        printf '%s\n' "$monitor_pid" >"$run_dir/monitor.pid"
    fi

    printf 'detached_run_dir=%s\n' "$run_dir"
    if [[ -f "$run_dir/systemd-unit" ]]; then
        printf 'monitor_unit=%s\n' "$(<"$run_dir/systemd-unit")"
    fi
    if [[ -f "$run_dir/monitor.pid" ]]; then
        printf 'monitor_pid=%s\n' "$(<"$run_dir/monitor.pid")"
    fi
    printf 'status_file=%s/status\n' "$run_dir"
    printf 'harness_log=%s/harness.log\n' "$run_dir"
    printf 'summary_file=%s/summary.tsv\n' "$run_dir"
}

status_run() {
    local run_dir="$1"
    local pid=""
    local unit=""
    local alive="unknown"
    local status_value="unknown"

    if [[ ! -d "$run_dir" ]]; then
        printf 'detached run directory not found: %s\n' "$run_dir" >&2
        exit 66
    fi
    if [[ -f "$run_dir/monitor.pid" ]]; then
        pid="$(<"$run_dir/monitor.pid")"
    fi
    if [[ -f "$run_dir/systemd-unit" ]]; then
        unit="$(<"$run_dir/systemd-unit")"
    fi

    printf 'detached_run_dir=%s\n' "$run_dir"
    if [[ -n "$unit" ]]; then
        printf 'monitor_unit=%s\n' "$unit"
        if systemctl --user is-active --quiet "$unit" >/dev/null 2>&1; then
            alive="true"
        else
            alive="false"
        fi
        if systemctl --user show --property=MainPID --value "$unit" >/dev/null 2>&1; then
            pid="$(systemctl --user show --property=MainPID --value "$unit")"
            if [[ -n "$pid" && "$pid" != "0" ]]; then
                printf 'monitor_pid=%s\n' "$pid"
            fi
        fi
    elif [[ -n "$pid" ]]; then
        printf 'monitor_pid=%s\n' "$pid"
        if kill -0 "$pid" >/dev/null 2>&1; then
            alive="true"
        else
            alive="false"
        fi
    fi
    printf 'monitor_alive=%s\n' "$alive"
    if [[ -f "$run_dir/status" ]]; then
        status_value="$(<"$run_dir/status")"
    else
        status_value="unknown"
    fi
    printf 'status=%s\n' "$status_value"
    if [[ "$status_value" == "running" && "$alive" == "false" && ! -f "$run_dir/exit-code" ]]; then
        printf 'status_warning=monitor exited before writing exit-code\n'
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
    if [[ -s "$run_dir/loss-bands.tsv" ]]; then
        printf 'loss_bands_file=%s/loss-bands.tsv\n' "$run_dir"
        cat "$run_dir/loss-bands.tsv"
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
